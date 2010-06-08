from optparse import make_option
from django.core.management.base import BaseCommand
from django.template.defaultfilters import slugify
from django.db import connection, reset_queries
from django.contrib.auth.models import User, Group, Permission
from django.contrib.contenttypes.models import ContentType
from xml.dom import minidom
import os
import pyodbc
import gc
from urlparse import urlparse
from datetime import datetime
from rooibos.data.models import Collection, CollectionItem, Field, FieldValue, Record, FieldSet, FieldSetField, Vocabulary, VocabularyTerm
from rooibos.storage.models import Storage, Media
from rooibos.solr import SolrIndex
from rooibos.access.models import AccessControl, ExtendedGroup, ATTRIBUTE_BASED_GROUP, IP_BASED_GROUP
from rooibos.access import sync_access
from rooibos.util.progressbar import ProgressBar
from rooibos.presentation.models import Presentation, PresentationItem, PresentationItemInfo
from rooibos.contrib.tagging.models import Tag
from rooibos.util.models import OwnedWrapper
from rooibos.contrib.ipaddr import IP

# old permissions

P = dict(
    _None = 0,
    ModifyACL = 1 << 0,
    CreateCollection = 1 << 1,
    ManageCollection = 1 << 2,
    DeleteCollection = 1 << 3,
    ModifyImages = 1 << 5,
    ReadCollection = 1 << 7,
    CreateSlideshow = 1 << 8,
    ModifySlideshow = 1 << 9,
    DeleteSlideshow = 1 << 10,
    ViewSlideshow = 1 << 11,
    CopySlideshow = 1 << 12,
    FullSizedImages = 1 << 13,
    AnnotateImages = 1 << 14,
    ManageUsers = 1 << 15,
    ImageViewerAccess = 1 << 16,
    PublishSlideshow = 1 << 17,
    ResetPassword = 1 << 18,
    ManageAnnouncements = 1 << 21,
    ManageControlledLists = 1 << 23,
    ManageCollectionGroups = 1 << 25,
    UserOptions = 1 << 26,
    PersonalImages = 1 << 27,
    ShareImages = 1 << 28,
    SuggestImages = 1 << 29,
    Unknown = 1 << 31,
)


class Command(BaseCommand):
    help = 'Migrates database from MDID2'
    args = "config_file"
    option_list = BaseCommand.option_list + (
        make_option('--skip-users', dest='skip_users', action='store_true', help='Do not migrate user accounts'),
        make_option('--max-records', type='int', dest='max_records', action='store', help='Only migrate a certain number of records'),
        make_option('--collection', '-c', type='int', dest='collection_ids', action='append', help='Primary keys of collections to migrate'),
        make_option('--local', dest='local_only', action='store_true', help='Migrate local collections only'),
        make_option('--allow-anonymous', dest='anonymous', action='store_true', help='Make all collections available to anonymous users'),
        make_option('--skip-personal', dest='skip_personal', action='store_true', help='Do not migrate personal images'),
        make_option('--full-only', dest='full_images_only', action='store_true', help='Only migrate full-size images'),
    )

    def readConfig(self, file):
        connection = None
        servertype = None
        config = minidom.parse(file)
        for e in config.getElementsByTagName('database')[0].childNodes:
            if e.localName == 'connection':
                connection = e.firstChild.nodeValue
            elif e.localName == 'servertype':
                servertype = e.firstChild.nodeValue
        return (servertype, connection)


    def handle(self, *config_files, **options):
        if len(config_files) != 1:
            print "Please specify exactly one configuration file."
            return

        image_type = ContentType.objects.get_for_model(Record)        

        servertype, connection = self.readConfig(config_files[0])

        conn = None
        if servertype == "MSSQL":
            conn = pyodbc.connect('DRIVER={SQL Server};%s' % connection)
        elif servertype == "MYSQL":
            conn = pyodbc.connect('DRIVER={MySQL};%s' % connection)
        else:
            print "Unsupported database type"
            return

        cursor = conn.cursor()
        row = cursor.execute("SELECT Version FROM DatabaseVersion").fetchone()
        version = row.Version

        if not version in ("00006", "00007", "00008"):
            print "Database version is not supported"
            return

        print "Migrating from version %s" % version

        # Migrate users
        users = {}
        if not options.get('skip_users'):
            print "Migrating users"
            for row in cursor.execute("SELECT ID,Login,Password,Name,FirstName,Email,Administrator,LastAuthenticated " +
                                      "FROM Users"):
                user = User()
                user.username = row.Login[:30]
                if row.Password:
                    user.password = row.Password.lower()
                else:
                    user.set_unusable_password()
                user.last_name = row.Name[:30]
                user.first_name = row.FirstName[:30]
                user.email = row.Email[:75]
                user.is_superuser = user.is_staff = row.Administrator
                user.last_login = row.LastAuthenticated or datetime(1980, 1, 1)
                try:
                    user.save()
                    users[row.ID] = user
                except:
                    print "Warning: possible duplicate login detected: %s" % row.Login

        # Migrate user groups
        print "Migrating user groups"
        usergroups = {}
        for row in cursor.execute("SELECT ID,Title,Type FROM UserGroups"):
            if row.Type == 'M':
                usergroups[row.ID] = Group.objects.create(name=row.Title)
            else:
                usergroups[row.ID] = ExtendedGroup.objects.create(name=row.Title, type=row.Type)

        for row in cursor.execute("SELECT GroupID,Subnet,Mask FROM UserGroupIPRanges"):
            if usergroups.has_key(row.GroupID) and usergroups[row.GroupID].type == IP_BASED_GROUP:
                usergroups[row.GroupID].subnet_set.create(subnet=str(IP('%s/%s' % (row.Subnet, row.Mask))))

        for row in cursor.execute("SELECT GroupID,Attribute,AttributeValue FROM UserGroupAttributes"):
            if usergroups.has_key(row.GroupID) and usergroups[row.GroupID].type == ATTRIBUTE_BASED_GROUP:
                attr, created = usergroups[row.GroupID].attribute_set.get_or_create(attribute=row.Attribute)
                attr.attributevalue_set.create(value=row.AttributeValue)

        for row in cursor.execute("SELECT UserID,GroupID FROM UserGroupMembers"):
            if users.has_key(row.UserID):
                users[row.UserID].groups.add(usergroups[row.GroupID])

        # Migrate collections and collection groups

        print "Migrating collections"
        groups = {}
        groups_medium_dimensions = {}
        collgroups = {}
        storage = {}
        fieldsets = {}

        for row in cursor.execute("SELECT ID,Title FROM CollectionGroups"):
            collgroups[row.ID] = Collection.objects.create(title=row.Title)

        for row in cursor.execute("SELECT ID,Type,Title,Description,UsageAgreement,MediumImageHeight,MediumImageWidth,GroupID,ResourcePath FROM Collections"):
            if (not options.get('collection_ids') or (row.ID in options['collection_ids'])) and \
                (not options.get('local_only') or row.Type == 'I'):
                manager = None
                if row.Type == 'N':
                    manager = 'nasaimageexchange'
                groups[row.ID] = Collection.objects.create(title=row.Title, description=row.Description, agreement=row.UsageAgreement)
                if collgroups.has_key(row.GroupID):
                    collgroups[row.GroupID].children.add(groups[row.ID])
                if row.Type in ('I', 'N', 'R'):
                    base = row.ResourcePath.replace('\\', '/')
                    storage[row.ID] = dict()
                    storage[row.ID]['general'] = Storage.objects.create(title=row.Title[:91],
                                                                        system='local',
                                                                        base=base)
                    if not options.get('full_images_only'):
                        storage[row.ID]['full'] = Storage.objects.create(title=row.Title[:91] + ' (full)',
                                                                         system='local',
                                                                         base=os.path.join(base, 'full'))
                        storage[row.ID]['medium'] = Storage.objects.create(title=row.Title[:91] + ' (medium)',
                                                                           system='local',
                                                                           base=os.path.join(base, 'medium'))
                        storage[row.ID]['thumb'] = Storage.objects.create(title=row.Title[:91] + ' (thumb)',
                                                                          system='local',
                                                                          base=os.path.join(base, 'thumb'))
                fieldsets[row.ID] = FieldSet.objects.create(title='%s fields' % row.Title)

                groups_medium_dimensions[row.ID] = dict(height=row.MediumImageHeight, width=row.MediumImageWidth)

        # Migrate collection permissions

        def populate_access_control(ac, row, readmask, writemask, managemask, restrictions_callback=None):
            def tristate(mask):
                if row.DenyPriv and row.DenyPriv & mask: return False
                if row.GrantPriv and row.GrantPriv & mask: return True
                return None
            ac.read = tristate(readmask)
            ac.write = tristate(writemask)
            ac.manage = tristate(managemask)
            if row.UserID and users.has_key(row.UserID):
                ac.user = users[row.UserID]
            elif usergroups.has_key(row.GroupID):
                ac.usergroup = usergroups[row.GroupID]
            elif row.UserID == -1 and not options.get('anonymous'):
                pass
            else:
                return False
            if restrictions_callback:
                restrictions_callback(ac, row)
            return True

        # Migrate system permissions

        publish_permission = Permission.objects.get(codename='publish_presentations')
        for row in cursor.execute("SELECT ObjectID,UserID,GroupID,GrantPriv,DenyPriv " +
                                  "FROM AccessControl WHERE ObjectType='O' AND ObjectID=1"):            
            if row.DenyPriv and row.DenyPriv & P['PublishSlideshow']:
                continue
            if row.GrantPriv and row.GrantPriv & P['PublishSlideshow']:
                if row.UserID and users.has_key(row.UserID):
                    users[row.UserID].user_permissions.add(publish_permission)
                elif usergroups.has_key(row.GroupID):
                    usergroups[row.GroupID].permissions.add(publish_permission)

        #Privilege.ModifyACL  -> manage
        #Privilege.ManageCollection  -> manage
        #Privilege.DeleteCollection  -> manage
        #Privilege.ModifyImages  -> write
        #Privilege.ReadCollection  -> read
        #Privilege.FullSizedImages  -> read (applied to storage)
        #Privilege.AnnotateImages  -> n/a
        #Privilege.ManageControlledLists  -> manage
        #Privilege.PersonalImages  -> write (applied to general storage)
        #Privilege.ShareImages  -> n/a
        #Privilege.SuggestImages  -> n/a

        for row in cursor.execute("SELECT ObjectID,UserID,GroupID,GrantPriv,DenyPriv " +
                                  "FROM AccessControl WHERE ObjectType='C' AND ObjectID>0"):
            if not groups.has_key(row.ObjectID):
                continue
            # Collection
            ac = AccessControl()
            ac.content_object = groups[row.ObjectID]
            if populate_access_control(ac, row, P['ReadCollection'], P['ModifyImages'], P['ManageCollection']):
                ac.save()

            # full storage
            ac = AccessControl()
            if storage.has_key(row.ObjectID):
                if not options.get('full_images_only'):
                    ac.content_object = storage[row.ObjectID]['full']
                    if populate_access_control(ac, row, P['FullSizedImages'], P['ModifyImages'], P['ManageCollection']):
                        ac.save()
                    # medium storage
                    ac = AccessControl()
                    ac.content_object = storage[row.ObjectID]['medium']
                    if populate_access_control(ac, row, P['ReadCollection'], P['ModifyImages'], P['ManageCollection']):
                        ac.save()
                    # thumb storage
                    ac = AccessControl()
                    ac.content_object = storage[row.ObjectID]['thumb']
                    if populate_access_control(ac, row, P['ReadCollection'], P['ModifyImages'], P['ManageCollection']):
                        ac.save()
                # new general storage

                def general_restrictions(ac, row):
                    full_access = row.GrantPriv and row.GrantPriv & P['FullSizedImages']
                    if ac.read and not full_access:
                        ac.restrictions = groups_medium_dimensions[row.ObjectID]

                ac = AccessControl()
                ac.content_object = storage[row.ObjectID]['general']
                if populate_access_control(ac, row, P['ReadCollection'], P['ModifyImages'] | P['PersonalImages'], P['ManageCollection'],
                                           general_restrictions):
                    ac.save()

        if options.get('anonymous'):
            for id in groups.keys():
                AccessControl.objects.create(content_object=groups[id], read=True)
                if storage.has_key(id):
                    AccessControl.objects.create(content_object=storage[id]['general'], read=True)
                    if not options.get('full_images_only'):
                        AccessControl.objects.create(content_object=storage[id]['full'], read=True)
                        AccessControl.objects.create(content_object=storage[id]['medium'], read=True)
                        AccessControl.objects.create(content_object=storage[id]['thumb'], read=True)


        # Migrating controlled lists
        print "Migrating controlled lists"
        vocabularies = {}
        for row in cursor.execute("SELECT ID,Title,Description,Standard,Origin,CollectionID FROM ControlledLists"):
            vocabularies[row.ID] = Vocabulary.objects.create(title=row.Title,
                                                             description=row.Description,
                                                             standard=row.Standard,
                                                             origin=row.Origin)
            if groups.has_key(row.CollectionID):
                sync_access(groups[row.CollectionID], vocabularies[row.ID])

        for row in cursor.execute("SELECT ControlledListID,ItemValue FROM ControlledListValues"):
            VocabularyTerm.objects.create(vocabulary=vocabularies[row.ControlledListID],
                                          term=row.ItemValue)

        # Migrate fields

        print "Migrating fields"
        fields = {}
        standard_fields = dict((str(f), f) for f in Field.objects.all())

        for row in cursor.execute("""SELECT ID,CollectionID,Label,Name,DCElement,DCRefinement,
                                  ShortView,MediumView,LongView,ControlledListID
                                  FROM FieldDefinitions ORDER BY DisplayOrder"""):
            if groups.has_key(row.CollectionID):
                fields[row.ID] = Field.objects.create(label=row.Label, old_name=row.Name)
                dc = ('dc.%s%s%s' % (row.DCElement, row.DCRefinement and '.' or '', row.DCRefinement or '')).lower()
                if standard_fields.has_key(dc):
                    fields[row.ID].equivalent.add(standard_fields[dc])
                if vocabularies.has_key(row.ControlledListID):
                    vocabularies[row.ControlledListID].fields.add(fields[row.ID])
                FieldSetField.objects.create(fieldset=fieldsets[row.CollectionID],
                                             field=fields[row.ID],
                                             label=row.Label,
                                             order=fieldsets[row.CollectionID].fields.count() + 1,
                                             importance=(row.ShortView and 4) + (row.MediumView and 2) + (row.LongView and 1))

        # Migrate records and media

        print "Migrating records"
        images = {}
        count = 0
        pb = ProgressBar(list(cursor.execute("SELECT COUNT(*) AS C FROM Images"))[0].C)
        for row in cursor.execute("SELECT ID,CollectionID,Resource,Created,Modified,RemoteID," +
                                  "CachedUntil,Expires,UserID,Flags FROM Images"):
            if groups.has_key(row.CollectionID) and \
                (not options.get('skip_personal') or not row.UserID):
                
                if row.UserID:
                    if users.has_key(row.UserID):
                        owner = users[row.UserID]
                        flags = row.Flags or 0
                        shared = flags & 1
                        suggested = flags & 2
                        rejected = flags & 4
                    else:
                        continue
                else:
                    owner = shared = suggested = rejected = None
                
                image = Record.objects.create(created=row.Created or row.Modified or datetime.now(),
                                                name=row.Resource.rsplit('.', 1)[0],
                                                modified=row.Modified or datetime.now(),
                                                source=row.RemoteID,
                                                next_update=row.CachedUntil or row.Expires,
                                                owner=owner,
                                                )
                images[row.ID] = image.id
                CollectionItem.objects.create(record_id=image.id,
                                              collection=groups[row.CollectionID],
                                              hidden=True if owner and not shared else False)
                if storage.has_key(row.CollectionID):
                    if row.Resource.endswith('.xml'):
                        self.process_xml_resource(image, storage[row.CollectionID]["general"], row.Resource)
                    else:
                        if not options.get('full_images_only'):
                            for type in ('full', 'medium', 'thumb'):
                                Media.objects.create(
                                    record_id=image.id,
                                    name=type,
                                    url=row.Resource.strip(),
                                    storage=storage[row.CollectionID][type],
                                    mimetype='image/jpeg')
                        else:
                            Media.objects.create(
                                record_id=image.id,
                                name=row.Resource.rsplit('.', 1)[0],
                                url=os.path.join('full', row.Resource.strip()),
                                storage=storage[row.CollectionID]['general'],
                                mimetype='image/jpeg')
                            
                if owner and suggested and not rejected:
                    Tag.objects.update_tags(OwnedWrapper.objects.get_for_object(
                                user=owner, object_id=image.id, type=image_type),
                                'suggested')
                
            count += 1
            if count % 100 == 0:
                pb.update(count)
                reset_queries()
            if options.get('max_records') and count >= options['max_records']:
                break
        pb.done()

        # Migrate image notes
        
        print "Migrating image notes"
        for row in cursor.execute("SELECT ImageID,UserID,Annotation FROM ImageAnnotations"):
            if images.has_key(row.ImageID) and users.has_key(row.UserID):
                FieldValue.objects.create(record_id=images[row.ImageID],
                                              field=standard_fields["dc.description"],
                                              owner=users[row.UserID],
                                              label="Note",
                                              value=row.Annotation,
                                              order=1000)

        # Migrate favorite images

        print "Migrating favorite images"
        for row in cursor.execute("SELECT UserID,ImageID FROM FavoriteImages"):
            if images.has_key(row.ImageID) and users.has_key(row.UserID):
                Tag.objects.update_tags(OwnedWrapper.objects.get_for_object(
                                user=users[row.UserID], object_id=images[row.ImageID], type=image_type),
                                'favorite')

        # Migrate field values

        print "Migrating field values"
        count = 0
        pb = ProgressBar(list(cursor.execute("SELECT COUNT(*) AS C FROM FieldData"))[0].C)
        for row in cursor.execute("SELECT ImageID,FieldID,FieldValue,OriginalValue,Type,Label,DisplayOrder " +
                                  "FROM FieldData INNER JOIN FieldDefinitions ON FieldID=FieldDefinitions.ID"):
            if images.has_key(row.ImageID) and row.FieldValue:
                FieldValue.objects.create(record_id=images[row.ImageID],
                                          field=fields[row.FieldID],
                                          label=row.Label,
                                          value=row.FieldValue,
                                          order=row.DisplayOrder)
            count += 1
            if count % 100 == 0:
                pb.update(count)
                reset_queries()
        pb.done()                

        # Migrate folders
        # Nothing to do - folders replaced by tags

        # Migrate slideshows

        print "Migrating slideshows"
        slideshows = {}
        for row in cursor.execute("SELECT Slideshows.ID,Slideshows.UserID,Slideshows.Title,Description, \
                                  AccessPassword,CreationDate,ModificationDate,ArchiveFlag, \
                                  Folders.Title AS Folder FROM Slideshows LEFT JOIN Folders ON FolderID=Folders.ID"):
            if users.has_key(row.UserID):
                slideshows[row.ID] = Presentation.objects.create(title=row.Title,
                                                                 owner=users[row.UserID],
                                                                 description=row.Description,
                                                                 hidden=row.ArchiveFlag,
                                                                 password=row.AccessPassword)
                slideshows[row.ID].override_dates(created=row.CreationDate,
                                                  modified=row.ModificationDate)
                if row.Folder:
                    Tag.objects.update_tags(OwnedWrapper.objects.get_for_object(
                        user=users[row.UserID], object=slideshows[row.ID]),
                        '"%s"' % row.Folder.replace('"',"'"))

        print "Migrating slides"
        count = 0
        pb = ProgressBar(list(cursor.execute("SELECT COUNT(*) AS C FROM Slides"))[0].C)
        for row in cursor.execute("SELECT SlideshowID,ImageID,DisplayOrder,Scratch,Annotation FROM Slides"):
            if images.has_key(row.ImageID) and slideshows.has_key(row.SlideshowID):
                item = PresentationItem.objects.create(record_id=images[row.ImageID],
                                               presentation=slideshows[row.SlideshowID],
                                               order=row.DisplayOrder,
                                               hidden=row.Scratch)
                if row.Annotation:
                    item.annotation = row.Annotation

            count += 1
            if count % 100 == 0:
                pb.update(count)
        pb.done()


        # Migrate slideshow permissions

        #Privilege.ModifyACL -> n/a
        #Privilege.ModifySlideshow -> write
        #Privilege.DeleteSlideshow -> manage
        #Privilege.ViewSlideshow -> read
        #Privilege.CopySlideshow -> n/a

        for row in cursor.execute("SELECT ObjectID,UserID,GroupID,GrantPriv,DenyPriv " +
                                  "FROM AccessControl WHERE ObjectType='S' AND ObjectID>0"):
            if slideshows.has_key(row.ObjectID):
                ac = AccessControl()
                ac.content_object = slideshows[row.ObjectID]
                if populate_access_control(ac, row, P['ViewSlideshow'], P['ModifySlideshow'], P['DeleteSlideshow']):
                    ac.save()



    def process_xml_resource(self, record, storage, file):

        def node_text(node):
            return ''.join(n.nodeValue for n in node.childNodes).strip()

        def child_text(node, tagname):
            for e in node.getElementsByTagName(tagname):
                return node_text(e)
            return None

        def get_media(node):
            return dict(
                display = e.attributes['display'].nodeValue,
                type = e.attributes['type'].nodeValue,
                label = child_text(e, 'label'),
                link = child_text(e, 'link'),
                data = child_text(e, 'data'), )

        def make_html(link, label):
            if not link:
                return label
            else:
                return '<a href="%s">%s</a>' % (link, label)

        def name_from_url(url):
            return os.path.splitext(os.path.basename(urlparse(url)[2]))[0]

        try:
            ovcstorage = Storage.objects.get(name='onlinevideo')
        except Storage.DoesNotExist:
            ovcstorage = Storage.objects.create(title='Online Video Collection', name='onlinevideo', system='online')

        try:
            ovcstorage_full = Storage.objects.get(name='onlinevideo')
        except Storage.DoesNotExist:
            ovcstorage_full = Storage.objects.create(title='Online Video Collection (downloadable)', name='onlinevideo-full', system='online')

        description_field = Field.objects.get(standard__prefix='dc', name='description')

        file = os.path.join(storage.base, file)
        try:
            resource = minidom.parse(file)
        except:
            return
        thumb = None
        medium = []
        full = []
        for e in resource.getElementsByTagName('thumb'):
            thumb = child_text(e, 'image')
        for e in resource.getElementsByTagName('medium'):
            medium.append(get_media(e))
        for e in resource.getElementsByTagName('full'):
            full.append(get_media(e))

        Media.objects.create(
            record=record,
            name='thumb',
            url='thumb/%s' % thumb,
            storage=storage,
            mimetype='image/jpeg')

        for m in medium:
            if m['display'] == 'default':
                record.fieldvalue_set.create(field=description_field, value=make_html(m['link'], m['label']))
            else:
                Media.objects.create(
                    record=record,
                    name=name_from_url(m['link']),
                    url=m['link'],
                    storage=ovcstorage,
                    mimetype=m['type'])

        for m in full:
            if m['display'] == 'default':
                record.fieldvalue_set.create(value=make_html(m['link'], m['label']))
            else:
                Media.objects.create(
                    record=record,
                    name=name_from_url(m['link']),
                    url=m['link'],
                    storage=ovcstorage_full,
                    mimetype=m['type'])