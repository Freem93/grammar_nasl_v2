#TRUSTED 2792b173e6c1a86b29c40d36a70563253141e6aaf00fbbf4c1b9c8ab941a8f7fd34e91d49e9add793745495188e4ce2381fe0497166868ebfae5bc2be5ca3c0aabeb9941359ec8dad9e31daa1de6a6cff09934a98736313b7afe5c15226907d472268c3551c9f327481107e1f0b4388acc92967306e3d87cf7fd92bb8667653a782bffc9153375e52181adfad0913cac5cacb57b9645ecddf68d0121bdfb990b8d6f9a4fc5cf15dd3d084b634d36ff001108cca56e0496d4bb13c17e3754a1c0ef50ebef55af5a8108aeefb809fdfbe11fde44510edc9a8b79dc29729356f8952109950e307cc1b83a4c447cf1d37962cc1368ae3c804512ff750b50a32d118b82b71726808f330d38a6207b821a7cf874f3ea0043dc13e8d261f2a229ae520c904984b6a2e45d723f193f7884897522377fbe63826d5ac140180c7c3a92bed43bbfdf811c46ad51ec99676edbb95d1f39564b6f1d12e33f841682725cef3b84eff1a4636e71eccf903c260a142d1c8a032ce7d909256ca977f52bed724565ca2fd4c3f7515779ef0da739f05c81d22bdb06f7bf7fe4dcc05adb23dec57582a086720c900c72e5886d005d86f7097344167676ab9ad41599b328e50973a02e50b16218e1fc3019cae3f6c0687889405a5f520a59e9a3118a5dcab4e48746f7f6361dc3c546bbd2d979dc894bfaa0433bc04663e6b4454f2a9eb5403dcf7c315c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93345);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/09/26");

  script_cve_id(
    "CVE-2016-2207",
    "CVE-2016-2209",
    "CVE-2016-2210",
    "CVE-2016-2211",
    "CVE-2016-3644",
    "CVE-2016-3645",
    "CVE-2016-3646"
  );
  script_bugtraq_id(
    91431,
    91434,
    91435,
    91436,
    91437,
    91438,
    91439
  );
  script_osvdb_id(
    140636,
    140637,
    140638,
    140639,
    140640,
    140641,
    140642
  );

  script_name(english:"Symantec Protection Engine 7.0.x < 7.0.5 HF01 / 7.5.x < 7.5.3 HF03 / 7.8.x < 7.8.0 HF01 Multiple Vulnerabilities (SYM16-010) (*nix check)");
  script_summary(english:"Checks the version of Symantec Protection Engine.");

  script_set_attribute(attribute:"synopsis", value:
"A security application installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Protection Engine installed on the remote
host is 7.0.x prior to 7.0.5 HF01, 7.5.x prior to 7.5.3 HF03, or 7.8.x
prior to 7.8.0 HF01. It is, therefore, affected by multiple
vulnerabilities :

  - An array indexing error exists in the Unpack::ShortLZ()
    function within file unpack15.cpp due to improper
    validation of input when decompressing RAR files. An
    unauthenticated, remote attacker can exploit this, via
    a specially crafted file, to corrupt memory, resulting
    in a denial of service condition or the execution of
    arbitrary code. (CVE-2016-2207)

  - A stack-based buffer overflow condition exists when
    handling PowerPoint files due to improper validation of
    user-supplied input while handling misaligned stream
    caches. An unauthenticated, remote attacker can exploit
    this, via a specially crafted PPT file, to cause a
    denial of service condition or the execution of
    arbitrary code. (CVE-2016-2209)

  - A stack-based buffer overflow condition exists in the
    CSymLHA::get_header() function within file Dec2LHA.dll
    due to improper validation of user-supplied input when
    decompressing LZH and LHA archive files. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted archive file, to cause a denial of
    service condition or the execution of arbitrary code.
    (CVE-2016-2210)

  - Multiple unspecified flaws exist in libmspack library
    due to improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit these, via
    a specially crafted CAB file, to corrupt memory,
    resulting in a denial of service condition or the
    execution of arbitrary code. (CVE-2016-2211)

  - A heap buffer overflow condition exists in the
    CMIMEParser::UpdateHeader() function due to improper
    validation of user-supplied input when parsing MIME
    messages. An unauthenticated, remote attacker can
    exploit this, via a specially crafted MIME message, to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2016-3644)

  - An integer overflow condition exists in the
    Attachment::setDataFromAttachment() function within file
    Dec2TNEF.dll due to improper validation of user-supplied
    input when decoding TNEF files. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted TNEF file, to cause a denial of service
    condition or the execution of arbitrary code.
    (CVE-2016-3645)

  - An array indexing error exists in the
    ALPkOldFormatDecompressor::UnShrink() function within
    the scan engine decomposer due to improper validation of
    input when decoding ZIP files. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted ZIP file, to corrupt memory, resulting in a
    denial of service condition or the execution of
    arbitrary code. (CVE-2016-3646)");
  # https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20160628_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?175e28a5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Protection Engine version 7.0.5 HF01, 7.5.3 HF03,
7.8.0 HF01 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:protection_engine");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("symantec_protection_engine.nbin");
  script_require_keys("installed_sw/Symantec Protection Engine");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("hostlevel_funcs.inc");
include("install_func.inc");

app = 'Symantec Protection Engine';
port = NULL;
function check_hf(path)
{
  local_var cmd, ret, buf, match, ver;
  local_var line, matches, vuln;

  vuln = FALSE;
  cmd = "cat -v " + path + "/bin/libdec2.so";

  if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

  port = kb_ssh_transport();
  if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

  ret = ssh_open_connection();
  if (!ret) exit(1, 'ssh_open_connection() failed.');


  buf = ssh_cmd(cmd:cmd);
  if(!empty_or_null(buf)){
    match = eregmatch(pattern:"Decomposer\^@(\d\.\d\.\d\.\d)",string:buf);
    ver = match[1];
    if(ver_compare(ver:ver, fix:"5.4.6.2", strict:FALSE) < 0) vuln = TRUE;
  }
  else audit(AUDIT_UNKNOWN_APP_VER, "Symantec Protection Engine: Decomposer Engine");
  return vuln;
}

install = get_single_install(app_name:app);
version = install["version"];
path = install["path"];
path = chomp(path);

fix = NULL;

if (version =~ "^7\.0\.[0-9.]+$")
{
  if (
    version =~ "^7\.0\.5\." &&
    check_hf(path:path)
  ) fix = "7.0.5 HF01";

  if (version =~ "^7\.0\.[0-4]\.")
    fix = "7.0.5 HF01";
}
else if (version =~ "^7\.5\.[0-9.]+$")
{
  if (
    version =~ "^7\.5\.3\." &&
    check_hf(path:path)
  ) fix = "7.5.3 HF03";

  if (version =~ "^7\.5\.[0-2]\.")
    fix = "7.5.3 HF03";
}
else if (version =~ "^7\.8\.[0-9.]+$")
{
  if (
    version =~ "^7\.8\.0\." &&
    check_hf(path:path)
  ) fix = "7.8.0 HF01";
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);

if (!empty_or_null(fix))
{
  report +=
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';

  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
