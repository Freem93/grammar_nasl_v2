#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93225);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/27 14:39:36 $");

  script_cve_id("CVE-2016-0293");
  script_bugtraq_id(92593);
  script_osvdb_id(141451);

  script_name(english:"IBM BigFix Server 9.2.x < 9.2.8.74 .beswrpt File Handling XSS");
  script_summary(english:"Checks the version of the IBM BigFix Server.");

  script_set_attribute(attribute:"synopsis", value:
"An infrastructure management application running on the remote host
is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IBM BigFix Server
running on the remote host is version 9.2.x prior to 9.2.8.74. It is,
therefore affected by a reflected cross-site scripting vulnerability
when handling .beswrpt files due to improper validation of input
before returning it to users. An unauthenticated, remote attacker can
exploit this, via a specially crafted URL, to execute arbitrary script
code in a user's browser session.

IBM BigFix was formerly known as Tivoli Endpoint Manager, IBM Endpoint
Manager, and IBM BigFix Endpoint Manager.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21985743");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM BigFix Server version 9.2.8.74 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_endpoint_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:bigfix_platform");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ibm_tem_detect.nasl");
  script_require_keys("www/BigFixHTTPServer");
  script_require_ports("Services/www", 52311);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app_name = "IBM BigFix Server";
port = get_http_port(default:52311, embedded:FALSE);

version = get_kb_item_or_exit("www/BigFixHTTPServer/"+port+"/version");

if (version == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_WEB_SERVER_VER, app_name, port);

# 9.2 is affected
if (version !~ '^9\\.2\\.')
  audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);

if (version !~ "^(\d+\.){2,}\d+$")
  audit(AUDIT_VER_NOT_GRANULAR, app_name, port, version);

fix = "9.2.8.74";

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report = "";

  source = get_kb_item("www/BigFixHTTPServer/"+port+"/source");
  if (!isnull(source))
    report += '\n  Source            : ' + source;

  report +=
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING, xss:TRUE);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);
