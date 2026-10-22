"""Webshell signatures: real-world shells must hit, normal CMS code must not."""

import pytest

from php2shell_scanner.models import Severity
from php2shell_scanner.signatures import printable, scan
from php2shell_scanner.signatures.webshell import CONTENT_SIGNATURES


def hits(code: str) -> set:
    return {m.signature.rule for m in scan(CONTENT_SIGNATURES, code.encode())}


@pytest.mark.parametrize("code, rule", [
    ("<?php @eval($_POST['pass']);?>", "WEB-EVAL-INPUT"),
    ("<?php eval(base64_decode($_REQUEST['x'])); ?>", "WEB-EVAL-INPUT"),
    ("<?php assert(${'_POST'}['a']);", "WEB-EVAL-INPUT"),
    ("<?php system($_GET['cmd']);", "WEB-EXEC-INPUT"),
    ("<?php echo shell_exec($_REQUEST[c]);", "WEB-EXEC-INPUT"),
    ("<?=`$_GET[1]`?>", "WEB-BACKTICK-INPUT"),
    ("<?php $o = `$_POST[c]`; echo $o;", "WEB-BACKTICK-INPUT"),
    ("<?php $_GET['f']($_POST['x']);", "WEB-INPUT-AS-FUNC"),
    ("<?php call_user_func($_POST['f'], $_POST['a']);", "WEB-CALLBACK-INPUT"),
    ("<?php array_map($_GET['c'], array($_GET['d']));", "WEB-CALLBACK-INPUT"),
    ("<?php $f = create_function('', $_POST['code']); $f();", "WEB-CREATE-FUNC-INPUT"),
    ("<?php eval(file_get_contents('php://input'));", "WEB-EVAL-PHPINPUT"),
    ('<?php $key="e45e329feb5d925b"; $_SESSION[\'k\']=$key;', "WEB-BEHINDER"),
    ("<?php $pass='pass'; $payloadName='payload'; $key='3c6e0b8a9c15224a';", "WEB-GODZILLA"),
    ("<?php $shell = 'uname -a; w; id; /bin/sh -i';", "WEB-REVSHELL"),
    ("<?php include($_GET['p'] . '/tmp/sess_' . $id);", "WEB-SESSION-INCLUDE"),
    ("<?php echo '___START___'; system('id');", "WEB-POC-MARKER"),
    ("<?php file_put_contents($_GET['n'], $_POST['c']);", "WEB-FILE-WRITE-INPUT"),
    ("<?php $a = $_GET['a']; $a($_POST['b']);", "WEB-VAR-FUNC-INPUT"),
    ("<?php preg_replace('/.*/e', $_POST['c'], '');", "WEB-PREG-E"),
    ("<?php eval(gzinflate(base64_decode('S0tKAQA=')));", "WEB-OBFUSCATED-EVAL"),
    ("<?php // FilesMan\n$auth_pass = '';", "WEB-KNOWN-KIT"),
    ("<?php $x = " + "chr(97)." * 14 + "chr(97);", "WEB-CHR-OBFUSCATION"),
    ("<?php class Evil { public $cmd; function __destruct(){} }", "WEB-POC-GADGET"),
    ("<?php include($_GET['page']);", "WEB-INCLUDE-INPUT"),
])
def test_webshell_detected(code, rule):
    assert rule in hits(code)


@pytest.mark.parametrize("code", [
    # WordPress / Laravel / generic application code
    "<?php if ( isset( $_POST['log'] ) ) { $user = sanitize_user( $_POST['log'] ); }",
    "<?php $pdo->exec($_POST['sql']);",          # SQL injection, not an OS command sink
    "<?php $stmt = $db->query('SELECT 1'); $redis->eval($script);",
    "<?php $data = array_filter($_POST); $clean = array_map('trim', $_POST);",
    "<?php // value comes from $_GET['page'] (if set)\n$page = 1;",
    "<?php preg_replace('/\\s+/', ' ', $text); $path = '/home/user';",
    "<?php echo htmlspecialchars($_GET['q'], ENT_QUOTES);",
    "<?php $result = curl_exec($ch); exec('ls -la', $out);",
    "<?php // Silence is golden.",
    "<?php $sql = \"SELECT `name` FROM `t` WHERE id=\" . (int)$_GET['id'];",
])
def test_benign_code_not_flagged(code):
    strong = {m.signature.rule for m in scan(CONTENT_SIGNATURES, code.encode())
              if m.signature.severity >= Severity.MEDIUM}
    assert strong == set(), strong


def test_printable_escapes_control_chars_and_truncates():
    text = printable(b"a\x00b\x1b[31mc" + b"x" * 500, width=40)
    assert "\x1b" not in text and "\\x00" in text
    assert len(text) == 40 and text.endswith("...")


def test_octal_mixed_include_path():
    assert "WEB-INCLUDE-ENCODED" in hits('<?php @include "\\057va\\162/w\\167w/\\150tml/x.ico";')
    assert "WEB-INCLUDE-ENCODED" not in hits('<?php include "templates/header.php";')
