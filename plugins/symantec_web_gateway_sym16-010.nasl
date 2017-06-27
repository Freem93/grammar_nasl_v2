#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92001);
  script_version("$Revision: 1.9 $");
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

  script_name(english:"Symantec Web Gateway Anti-Virus Definition < 20160628.037 Multiple Vulnerabilities (SYM16-010) (credentialed check)");
  script_summary(english:"Checks the SWG AV definition version.");

  script_set_attribute(attribute:"synopsis", value:
"A web security application hosted on the remote web server is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported anti-virus definition version number,
the remote web server is hosting a version of Symantec Web Gateway
with an anti-virus definition version prior to 20160628.037. It is,
therefore, affected by multiple vulnerabilities :

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
  script_set_attribute(attribute:"solution", value:
"Upgrade the Symantec Web Gateway Anti-Virus definitions to version
20160628.037 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:web_gateway");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("symantec_web_gateway_detect.nasl");
  script_require_keys("installed_sw/symantec_web_gateway");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("install_func.inc");

app_name = 'Symantec Web Gateway';
app = 'symantec_web_gateway';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:443, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

av_ver = get_kb_item_or_exit('www/' + port + '/symantec_web_gateway/av_def_ver');
dir = install['path'];
ver = install['version'];
url = build_url(port:port, qs:dir);
av_fix = '20160628.037';

if (ver_compare(ver:av_ver, fix:av_fix, strict:FALSE) < 0)
{
  report =
    '\n  URL                           : ' + url +
    '\n  Installed application version : ' + ver +
    '\n  Installed anti-virus version  : ' + av_ver +
    '\n  Fixed anti-virus version      : ' + av_fix + '\n';

  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name + " Anti-Virus definition", url, av_ver);
