#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90024);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/19 15:55:07 $");

  script_cve_id("CVE-2016-0782");
  script_osvdb_id(135723);

  script_name(english:"Apache ActiveMQ 5.11.x < 5.11.4 / 5.12.x < 5.12.3 / 5.13.x < 5.13.1 Web Console Multiple XSS");
  script_summary(english:"Checks the version of ActiveMQ.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application that is affected by
multiple cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache ActiveMQ running on the remote host is 5.11.x
prior to 5.11.4, 5.12.x prior to 5.12.3, or 5.x prior to 5.13.1. It
is, therefore, affected by multiple cross-site scripting
vulnerabilities in the web-based administration console due to
improper validation of user-supplied input. A remote attacker can
exploit this, via a specially crafted request, to execute arbitrary
script code in a user's browser session.");
  # http://activemq.apache.org/security-advisories.data/CVE-2016-0782-announcement.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?41dd5ff8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache ActiveMQ version 5.11.4 / 5.12.3 / 5.13.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:activemq");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
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

fix = NULL;

if (version =~ "^5\.13\." && ver_compare(ver:version, fix:"5.13.1", strict:FALSE) == -1)
  fix = "5.13.1";
else if (version =~ "^5\.12\." && ver_compare(ver:version, fix:"5.12.3", strict:FALSE) == -1)
  fix = "5.12.3";
else if (version =~ "^5\.11\." && ver_compare(ver:version, fix:"5.11.4", strict:FALSE) == -1)
  fix = "5.11.4";
else if (version =~ "^5\.([0-9]|10)(\.|$)")
  fix = "5.11.4 / 5.12.3 / 5.13.1";

if (isnull(fix))
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);

report =
  '\n  URL               : ' + install_url +
  '\n  Installed version : ' + version +
  '\n  Fixed version     : ' + fix +
  '\n';

security_report_v4(extra:report, port:port, severity:SECURITY_WARNING, xss:TRUE);
