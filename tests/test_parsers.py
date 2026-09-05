import json

import pytest

from opentapeout.parsers import MAX_REPORT, parse, validate_result
from opentapeout.util import TapeoutError, canonical, loads


def result(**extra):
    return {"schema":"opentapeout.result/v1","run_id":"run-1","status":"pass","complete":True,
            "metrics":{},"violations":[],**extra}


def test_normalized_json_roundtrip():
    value=result(metrics={"wns_ns":0.125})
    assert parse(canonical(value),"json","run-1")==value


@pytest.mark.parametrize("status",["PASS","ok",True,False,0,"",None])
def test_unknown_status_rejected(status):
    with pytest.raises(TapeoutError):validate_result(result(status=status),"run-1")


@pytest.mark.parametrize("complete",["true",1,0,None,[],{}])
def test_completion_must_be_boolean(complete):
    with pytest.raises(TapeoutError):validate_result(result(complete=complete),"run-1")


@pytest.mark.parametrize("metric",[float('nan'),float('inf'),float('-inf'),True,"1.0",None,[]])
def test_metrics_must_be_finite_numbers(metric):
    with pytest.raises(TapeoutError):validate_result(result(metrics={"m":metric}),"run-1")


def test_pass_with_violations_is_invalid(violation):
    with pytest.raises(TapeoutError):validate_result(result(violations=[violation]),"run-1")


def test_incomplete_pass_is_invalid():
    with pytest.raises(TapeoutError):validate_result(result(complete=False),"run-1")


def test_duplicate_violation_fingerprints_rejected(violation):
    with pytest.raises(TapeoutError,match="Duplicate violation"):
        validate_result(result(status="fail",violations=[violation,violation]),"run-1")


def test_wrong_fingerprint_rejected(violation):
    with pytest.raises(TapeoutError,match="fingerprint"):
        validate_result(result(status="fail",violations=[{**violation,"fingerprint":"fake"}]),"run-1")


@pytest.mark.parametrize("blob",[b'{"x":1,"x":2}',b'{"x":NaN}',b'{"x":Infinity}',b'{bad',b'\xff'])
def test_strict_json_rejects_ambiguity(blob):
    with pytest.raises(TapeoutError):loads(blob)


def test_unknown_report_format_is_not_autodetected():
    with pytest.raises(TapeoutError):parse(b"PASS", "vendor-log", "run-1")


def test_unknown_json_fields_do_not_silently_disappear():
    with pytest.raises(TapeoutError):validate_result(result(warnings_ignored=True),"run-1")


def test_json_report_run_binding():
    with pytest.raises(TapeoutError):validate_result(result(),"run-2")


def test_junit_success_requires_tests():
    good=b'<testsuite tests="1" failures="0"><testcase name="equivalence"/></testsuite>'
    assert parse(good,"junit","r")["status"]=="pass"
    with pytest.raises(TapeoutError):parse(b'<testsuite tests="0"/>',"junit","r")


@pytest.mark.parametrize("tag",["failure","error","skipped"])
def test_junit_nonpasses_are_not_silently_ignored(tag):
    xml=f'<testsuite tests="1"><testcase name="t"><{tag} message="fixture"/></testcase></testsuite>'.encode()
    parsed=parse(xml,"junit","r")
    assert parsed["status"] != "pass"
    assert len(parsed["violations"])==1


def test_junit_declared_count_must_match():
    with pytest.raises(TapeoutError):
        parse(b'<testsuite tests="12"><testcase name="t"/></testsuite>',"junit","r")


@pytest.mark.parametrize("xml",[
    b'<!DOCTYPE testsuite [<!ENTITY x "payload">]><testsuite><testcase name="&x;"/></testsuite>',
    b'<!DOCTYPE report-database SYSTEM "file:///etc/passwd"><report-database/>',
    b'<testsuite><testcase>',
    '<?xml version="1.0" encoding="UTF-16"?><testsuite/>'.encode('utf-16'),
])
def test_xml_dtd_entities_truncation_and_unsupported_encodings_rejected(xml):
    with pytest.raises(TapeoutError):parse(xml,"junit","r")


def test_klayout_rdb_success_and_markers():
    empty=b'<report-database><categories/><cells/><items/></report-database>'
    assert parse(empty,"klayout-rdb","r")["status"]=="pass"
    xml=b'<report-database><categories/><cells/><items><item><cell>TOP</cell><category>width</category><values><value>edge</value></values></item></items></report-database>'
    parsed=parse(xml,"klayout-rdb","r")
    assert parsed["status"]=="fail" and parsed["violations"][0]["rule"]=="width"


@pytest.mark.parametrize("xml",[b'<report-database/>',b'<report-database><items/></report-database>',b'<wrong/>'])
def test_klayout_minimum_structure_required(xml):
    with pytest.raises(TapeoutError):parse(xml,"klayout-rdb","r")


def test_csv_header_and_violations():
    header=b'rule,location,message,severity\n'
    assert parse(header,"csv","r")["status"]=="pass"
    assert parse(header+b'width,top/u1,too narrow,error\n',"csv","r")["status"]=="fail"
    with pytest.raises(TapeoutError):parse(b'rule,message\nwidth,narrow\n',"csv","r")


def test_report_size_bounded():
    with pytest.raises(TapeoutError,match="size limit"):
        parse(b"x"*(MAX_REPORT+1),"json","r")


def test_junit_root_aggregate_count_checked():
    with pytest.raises(TapeoutError,match="count mismatch"):
        parse(b'<testsuites tests="9"><testsuite tests="1"><testcase name="t"/></testsuite></testsuites>',"junit","r")


def test_junit_suite_level_error_is_not_ignored():
    with pytest.raises(TapeoutError,match="Suite-level"):
        parse(b'<testsuite><error>startup failed</error><testcase name="t"/></testsuite>',"junit","r")


def test_float_overflow_is_not_a_json_number():
    with pytest.raises(TapeoutError):loads(b'{"number": 1e999}')
