import copy
import random

import pytest

from opentapeout.graph import Graph
from opentapeout.policy import default_policy,validate_policy
from opentapeout.util import TapeoutError,canonical,digest,identifier,safe_relative,timestamp,workspace_file


def node(value=1,deps=None,pins=None):
    return {"kind":"config","sha256":digest(value),"size":1,"path":None,"metadata":{"value":value},
            "depends_on":deps or [],"built_from":pins or {}}


def test_deep_graph_is_iterative():
    resources={"n0":node()}
    for i in range(1,5000):
        # Deliberately stale pins are fine for testing traversal, not releasable evidence.
        resources[f"n{i}"]=node(deps=[f"n{i-1}"])
    graph=Graph(resources)
    assert len(graph.closure(["n4999"]))==5000
    assert graph.stale["n4999"]


@pytest.mark.parametrize("seed",range(12))
def test_random_dag_fingerprints_and_reachability(seed):
    rng=random.Random(seed);resources={}
    for i in range(35):
        deps=rng.sample(list(resources),min(len(resources),rng.randrange(4)))
        prior=Graph(resources)
        resources[f"node-{i}"]=node(i,deps,{key:prior.fingerprints[key] for key in deps})
    graph=Graph(resources)
    assert all(not reasons for reasons in graph.stale.values())
    order={key:index for index,key in enumerate(graph.order)}
    assert all(order[dep]<order[key] for key,r in resources.items() for dep in r["depends_on"])
    reverse=Graph(dict(reversed(list(resources.items()))))
    assert graph.fingerprints==reverse.fingerprints


def test_missing_dependency_and_cycles_rejected():
    with pytest.raises(TapeoutError,match="Missing dependency"):Graph({"a":node(deps=["absent"])})
    with pytest.raises(TapeoutError,match="cycle"):Graph({"a":node(deps=["b"]),"b":node(deps=["a"])})


@pytest.mark.parametrize("path",["../secret","/etc/passwd","a/../../b","a//b","a/./b","a\\b","C:/file","", "a\x00b"])
def test_path_traversal_and_ambiguous_paths_rejected(path):
    with pytest.raises(TapeoutError):safe_relative(path)


def test_workspace_symlink_rejected(tmp_path):
    outside=tmp_path/"outside";outside.write_text("private")
    root=tmp_path/"root";root.mkdir();(root/"link").symlink_to(outside)
    with pytest.raises(TapeoutError,match="Symlink"):workspace_file(root,"link")


@pytest.mark.parametrize("ident",["","a/b","../a","a b","a\nb","<script>","x"*129])
def test_identifier_validation(ident):
    with pytest.raises(TapeoutError):identifier(ident)


@pytest.mark.parametrize("change",["empty_checks","empty_roles","duplicate_check","unknown_field","bool_as_age","nan_age","bad_bounds","string_bool","empty_metric"])
def test_policy_fail_closed_validation(change):
    policy=default_policy()
    if change=="empty_checks":policy["required_checks"]=[]
    elif change=="empty_roles":policy["approval_roles"]=[]
    elif change=="duplicate_check":policy["required_checks"].append(copy.deepcopy(policy["required_checks"][0]))
    elif change=="unknown_field":policy["allow_stale"]=True
    elif change=="bool_as_age":policy["required_checks"][0]["max_age_hours"]=True
    elif change=="nan_age":policy["required_checks"][0]["max_age_hours"]=float('nan')
    elif change=="bad_bounds":policy["required_checks"][0]["metrics"]={"wns":{"min":1,"max":0}}
    elif change=="string_bool":policy["require_managed_runs"]="true"
    elif change=="empty_metric":policy["required_checks"][0]["metrics"]={"wns":{}}
    with pytest.raises(TapeoutError):validate_policy(policy)


def test_canonical_order_independence():
    assert canonical({"b":2,"a":1})==canonical({"a":1,"b":2})
    assert digest({"a":1})!=digest({"a":"1"})


def test_timezone_required():
    with pytest.raises(TapeoutError):timestamp("2026-09-05T10:00:00")


@pytest.mark.parametrize("mutation",["edit","add","delete"])
def test_directory_capture_detects_all_content_changes(ctx,mutation):
    from opentapeout.engine import object_refs
    folder=ctx.root/"technology";folder.mkdir();(folder/"layers.map").write_text("layers v1")
    ctx.engine.register_tree("full-pdk","pdk","technology",version="1")
    ctx.run();ctx.candidate();ctx.approve()
    assert ctx.gate()["ready"]
    refs=object_refs(ctx.engine.state()["candidates"]["RC1"])
    tree=ctx.engine.state()["resources"]["full-pdk"]["metadata"]
    assert tree["files"][0]["sha256"] in refs
    if mutation=="edit":(folder/"layers.map").write_text("layers v2")
    if mutation=="add":(folder/"extra.map").write_text("new")
    if mutation=="delete":(folder/"layers.map").unlink()
    assert any(b["code"]=="WORKSPACE_DRIFT" and b["scope"]=="full-pdk" for b in ctx.gate()["blockers"])


def test_directory_capture_rejects_links_and_empty_directories(ctx):
    folder=ctx.root/"technology";folder.mkdir()
    with pytest.raises(TapeoutError,match="Empty"):
        ctx.engine.register_tree("full-pdk","pdk","technology",version="1")
    (folder/"linked").symlink_to(ctx.root/"rtl.v")
    with pytest.raises(TapeoutError,match="Symlinks"):
        ctx.engine.register_tree("full-pdk","pdk","technology",version="1")
