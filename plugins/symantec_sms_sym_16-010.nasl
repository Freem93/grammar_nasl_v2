#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(91915);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/09/26 14:31:38 $");

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

  script_name(english:"Symantec Mail Security for Exchange / Domino Decomposer Engine Multiple Vulnerabilities (SYM16-010)");
  script_summary(english:"Checks the version of Dec2.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has software installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Mail Security for Exchange or Domino installed
on the remote Windows host is affected by multiple vulnerabilities in
the decomposer engine :

  - An array indexing error exists in the UnRAR component in
    the Unpack::ShortLZ() function in unpack15.cpp that is
    triggered when decompressing RAR files. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted RAR file, to corrupt memory, resulting
    in the execution of arbitrary code. (CVE-2016-2207)

  - An overflow condition exists when handling PowerPoint
    documents due to improper validation of user-supplied 
    input when handling a misaligned stream-cache. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted PPT file, to cause a stack-based
    buffer overflow, resulting in the execution of arbitrary
    code. (CVE-2016-2209)

  - An overflow condition exists in the
    CSymLHA::get_header() function in Dec2LHA.dll that is
    triggered when decompressing LZH and LHA archives. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted file, to cause a stack-based buffer
    overflow, resulting in the execution of arbitrary code.
    (CVE-2016-2210)

  - Multiple flaws exist in the libmspack library due to
    improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit these
    issues, via a specially crafted file, to crash processes
    linked against the library or execute arbitrary code.
    (CVE-2016-2211)

  - An overflow condition exists in the
    CMIMEParser::UpdateHeader() function due to improper
    validation of user-supplied input when parsing MIME
    messages. An unauthenticated, remote attacker can
    exploit this, via a specially crafted MIME message, to
    cause a heap-based buffer overflow, resulting in a
    denial of service condition or the execution of
    arbitrary code. (CVE-2016-3644)

  - An array indexing error exists in the scan engine
    decomposer in the LPkOldFormatDecompressor::UnShrink()
    function that is triggered when decoding ZIP archives.
    An unauthenticated, remote attacker can exploit this,
    via a specially crafted ZIP file, to cause a denial of
    service condition or the execution of arbitrary code.
    (CVE-2016-3645)

  - An integer overflow condition exists in the
    Attachment::setDataFromAttachment() function in
    Dec2TNEF.dll that is triggered when decoding TNEF files.
    An unauthenticated, remote attacker can exploit this,
    via a specially crafted TNEF file, to cause a denial of
    service condition or the execution of arbitrary code.
    (CVE-2016-3646)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20160628_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?175e28a5");
  # https://googleprojectzero.blogspot.com/2016/06/how-to-compromise-enterprise-endpoint.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a965f2f9");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix per the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:mail_security");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("sms_for_domino.nasl", "sms_for_msexchange.nasl");
  script_require_keys("Symantec_Mail_Security/Installed");
  script_require_ports(139, 445);
  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");

get_kb_item_or_exit("Symantec_Mail_Security/Installed");

types = make_list("Domino", "Exchange");

# Ensure that the affected software is installed.
backend = NULL;
foreach type (types)
{
  if (get_kb_item("SMB/SMS_" + type + "/Installed"))
  {
    backend = type;
    break;
  }
}
if (isnull(backend) || (backend != 'Exchange' && backend != 'Domino'))
  audit(AUDIT_NOT_INST, "Symantec Mail Security for Domino or Exchange");

path    = get_kb_item_or_exit("SMB/SMS_" + type + "/Path");
version = get_kb_item_or_exit("SMB/SMS_" + type + "/Version");

app       = 'Symantec Mail Security for ' + backend;
dec2_fix  = "5.4.6.2";
dec2_path = NULL;

ver = split(version, sep:'.', keep:FALSE);
branch = ver[0] + '.' + ver[1];

if (backend == 'Exchange' && branch =~ "^(6\.5|7\.[05])")
  dec2_path = "\SMSMSE\" + branch + "\Server\";
else if (backend == 'Domino' && branch =~ "^8\.[01]")
  dec2_path = "\Decomposer\"; 

if (isnull(dec2_path)) audit(AUDIT_INST_PATH_NOT_VULN, app, branch, path);

dec2_path = hotfix_append_path(path:path, value:dec2_path + "Dec2.dll");
dec2_ver = hotfix_get_fversion(path:dec2_path);
hotfix_handle_error(error_code:dec2_ver['error'], file:dec2_path, exit_on_fail:TRUE);
hotfix_check_fversion_end();

dec2_ver = join(dec2_ver['value'], sep:'.');

if (ver_compare(ver:dec2_ver, fix:dec2_fix, strict:FALSE) >= 0)
  audit(AUDIT_INST_PATH_NOT_VULN, app + " decomposer engine", dec2_ver, path);

port = get_kb_item('SMB/transport');
if (isnull(port)) port = 445;

report =
  '\n  Product                             : ' + app + ' ' + branch +
  '\n  Path                                : ' + path +
  '\n  Installed decomposer engine version : ' + dec2_ver +
  '\n  Fixed decomposer engine version     : ' + dec2_fix +
  '\n';

security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
