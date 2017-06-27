#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95920);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/20 14:45:31 $");

  script_cve_id("CVE-2016-6810");
  script_bugtraq_id(94882);
  script_osvdb_id(148416);
  script_xref(name:"IAVB", value:"2016-B-0185");

  script_name(english:"Apache ActiveMQ 5.x < 5.14.2 Web-based Administration Console Unspecified XSS");
  script_summary(english:"Checks the version of ActiveMQ.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache ActiveMQ running on the remote host is 5.x prior
to 5.14.2. It is, therefore, affected by a cross-site scripting (XSS)
vulnerability in the web-based administration console due to improper
validation of user-supplied input. An unauthenticated, remote attacker
can exploit this, by convincing a user to follow a specially crafted
link, to execute arbitrary script code in a user's browser session.");
  # http://activemq.apache.org/security-advisories.data/CVE-2016-6810-announcement.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a49dee8c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache ActiveMQ version 5.14.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:activemq");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("activemq_web_console_detect.nasl");
  script_require_keys("installed_sw/ActiveMQ", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8161);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = 'ActiveMQ';
get_install_count(app_name:app, exit_if_zero:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:8161);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir     = install['path'];
version = install['version'];
install_url = build_url(port:port, qs:dir);

fix = '5.14.2';
vuln = FALSE;

if (version =~ "^5\.14\." && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
  vuln = TRUE;
else if (version =~ "^5\.([0-9]|1[0-3])(\.|$)")
  vuln = TRUE;

if (!vuln)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);

report =
  '\n  URL               : ' + install_url +
  '\n  Installed version : ' + version +
  '\n  Fixed version     : ' + fix +
  '\n';

security_report_v4(extra:report, port:port, severity:SECURITY_WARNING, xss:TRUE);
