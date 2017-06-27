#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91895);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

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
    91434,
    91436,
    91437,
    91438,
    91431,
    91439,
    91435
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

  script_name(english:"Symantec Endpoint Protection Client 12.1.x < 12.1 RU6 MP5 Multiple Vulnerabilities (SYM16-010)");
  script_summary(english:"Checks the SEP Client version.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Symantec Endpoint Protection Client installed on the
remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Endpoint Protection Client installed on the
remote host is 12.1 prior to 12.1 RU6 MP5. It is, therefore, affected
by multiple vulnerabilities :

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
"Upgrade to Symantec Endpoint Protection Client version 12.1 RU6 MP5 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:endpoint_protection");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("savce_installed.nasl");
  script_require_keys("Antivirus/SAVCE/version");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

app = 'Symantec Endpoint Protection Client';
vuln = FALSE;

display_ver = get_kb_item_or_exit('Antivirus/SAVCE/version');
edition = get_kb_item('Antivirus/SAVCE/edition');

if (isnull(edition)) edition = '';
else if (edition == 'sepsb') app += ' Small Business Edition';

fixed_ver = '12.1.7004.6500';

if (display_ver =~ "^12\.1\." && ver_compare(ver:display_ver, fix:fixed_ver, strict:FALSE) == -1)
{
  port = kb_smb_transport();

  report =
    '\n  Product           : ' + app +
    '\n  Installed version : ' + display_ver +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, display_ver);
