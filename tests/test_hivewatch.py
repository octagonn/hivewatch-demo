import os, sys, tempfile, time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
os.environ['HIVEWATCH_DB']=tempfile.mktemp(suffix='.sqlite')
os.environ['HIVEWATCH_IPAPI']='0'
os.environ['HIVEWATCH_INGEST_TOKEN']=''
from fastapi.testclient import TestClient
import main, db, geo, tailers
from sentinel import read_varint,write_varint,Incomplete
import pytest

@pytest.mark.parametrize('value',[0,1,127,128,255,770,2147483647])
def test_varint(value):
    data=write_varint(value)
    assert read_varint(data)==(value,len(data))

def test_partial_varint():
    with pytest.raises(Incomplete):read_varint(bytes([128]))

def test_database():
    i=db.insert_event({'ts':time.time(),'source':'synthetic','kind':'probe','severity':1,'ip':'192.0.2.1','is_private':1})
    assert any(e['id']==i for e in db.recent_events())

def test_log_parser():
    ev=tailers.parse_mc_line('[12:34:56] [Server thread/INFO]: DemoPlayer[/192.0.2.1:50000] logged in with entity id 1','demo')
    assert ev['kind']=='login' and ev['username']=='DemoPlayer'

def test_write_auth_and_static(monkeypatch):
    c=TestClient(main.app)
    assert c.post('/api/clear').status_code==401
    assert c.post('/api/ingest',json={'ip':'192.0.2.1','is_private':1}).status_code==401
    monkeypatch.setattr(main,'INGEST_TOKEN','synthetic-test-token')
    assert c.post('/api/clear',headers={'X-Hivewatch-Token':'wrong'}).status_code==401
    assert c.post('/api/ingest',headers={'X-Hivewatch-Token':'synthetic-test-token'},json={'ip':'192.0.2.1','kind':'probe'}).json()['accepted']==1
    assert c.get('/').status_code==200
    assert c.get('/api/config').json()['home']['lat']==0
    assert geo.ENABLE_IPAPI is False
