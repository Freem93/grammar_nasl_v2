#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91896);
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

  script_name(english:"Symantec Messaging Gateway 10.x < 10.6.1-4 Multiple Vulnerabilities (SYM16-010)");
  script_summary(english:"Checks the Symantec Messaging Gateway version number.");

  script_set_attribute(attribute:"synopsis", value:
"A messaging security application running on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Symantec Messaging
Gateway (SMG) running on the remote host is 10.x prior to 10.6.1-4. It
is, therefore, affected by multiple vulnerabilities :

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
"Upgrade to Symantec Messaging Gateway version 10.6.1-4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:messaging_gateway");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("symantec_messaging_gateway_detect.nasl");
  script_require_keys("www/sym_msg_gateway");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

get_install_count(app_name:'sym_msg_gateway', exit_if_zero:TRUE);

port = get_http_port(default:443);
install = get_single_install(app_name:'sym_msg_gateway', port:port);
base_url = build_url(qs:install['dir'], port:port);

if (install['version'] == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_WEB_APP_VER, 'Symantec Messaging Gateway', base_url);
if (install['version'] !~ "^10(\.|$)")
  audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Symantec Messaging Gateway', base_url, install['version']);
if (install['version'] =~ "^10(\.6)?$") audit(AUDIT_VER_NOT_GRANULAR, 'Symantec Messaging Gateway', port, install['version']);

# Detection does not provide anything more detailed
# than 'x.y.z'.
if (install['version'] == "10.6.1" && report_paranoia < 2)
  audit(AUDIT_PARANOID);

if (
  install['version'] =~ "^10\.[0-5]($|[^0-9])" ||
  install['version'] =~ "^10\.6\.0($|[^0-9])"  ||
  install['version'] =~ "^10\.6\.1($|[^0-9\-]|(-[0-3])($|[^0-9]))"
)
{
  report =
    '\n  URL               : ' + base_url +
    '\n  Installed version : ' + install['version'] +
    '\n  Fixed version     : 10.6.1-4\n';
  if (install['version'] =~ "^10\.6\.1")
  {
    report += 
      '\n  Note that Nessus could not verify the granular patch level of the host.' +
      '\n  To avoid false alarms, turn off Report Paranoia.\n';
  }
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Symantec Messaging Gateway', base_url, install['version']);
