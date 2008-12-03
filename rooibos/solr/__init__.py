from datetime import datetime
import re
from django.conf import settings
from rooibos.data.models import Record, Group, Field
from pysolr import Solr

SOLR_EMPTY_FIELD_VALUE = 'unspecified'

class SolrIndex():
    
    def __init__(self):
        self._clean_string_re = re.compile('[\x00-\x08\x0b\x0c\x0e-\x1f]')
    
    def search(self, q, sort=None, start=None, rows=None, facets=None, facet_limit=-1, facet_mincount=0):
        conn = Solr(settings.SOLR_URL)
        result = conn.search(q, sort=sort, start=start, rows=rows, facets=facets, facet_limit=facet_limit, facet_mincount=facet_mincount)
        ids = [int(r['id']) for r in result]
        records = Record.objects.in_bulk(ids)
        return (result.hits, filter(None, map(lambda i: records.get(i), ids)), result.facets)
        
    def clear(self):
        from models import RecordInfo
        RecordInfo.objects.all().delete()
        conn = Solr(settings.SOLR_URL)
        conn.delete(q='*:*')    
        
    def optimize(self):
        conn = Solr(settings.SOLR_URL)
        conn.optimize()
    
    def index(self, verbose=False):
        from models import RecordInfo
        self._build_group_tree()
        conn = Solr(settings.SOLR_URL)
        records = Record.objects.filter(recordinfo=None)
        required_fields = Field.objects.filter(standard__prefix='dc').values_list('name', flat=True)
        count = 0
        docs = []
        for record in records:
            docs += [self._record_to_solr(record, required_fields)]
            count += 1
            if len(docs) % 1000 == 0:
                conn.add(docs)
                docs = []
            RecordInfo.objects.create(record=record, last_index=datetime.now())
            if verbose and count % 100 == 0:
                print "\r%s" % count,
        if docs:
            conn.add(docs)
    
        print "\r%s" % count
    
    def _record_to_solr(self, record, required_fields):
        required_fields = dict((f,None) for f in required_fields)
        doc = { 'id': str(record.id) }
        for v in record.fieldvalue_set.all():
            required_fields.pop(v.field.name, None)
            doc[v.field.name + '_t'] = [self._clean_string(v.value)] + (doc.get(v.field.name + '_t') or [])
        for f in required_fields:
            doc[f + '_t'] = SOLR_EMPTY_FIELD_VALUE
        parents = record.group_set.values_list('id', flat=True)
        # Combine the direct parents with (great-)grandparents
        doc['groups'] = list(reduce(lambda x,y:set(x)|set(y),[self.parent_groups[p] for p in parents],parents))
        if record.owner_id:
            doc['owner'] = record.owner_id
        return doc    
    
    def _clean_string(self, s):
        return self._clean_string_re.sub(' ', s)
    
    # A record in a group also belongs to all parent groups
    # This method builds a simple lookup table to quickly find all parent groups
    def _build_group_tree(self):
        self.parent_groups = {}
        for group in Group.objects.all():
            self.parent_groups[group.id] = [g.id for g in group.all_parent_groups]

