#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90025);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/19 15:55:07 $");

  script_cve_id("CVE-2016-0734", "CVE-2016-0782");
  script_bugtraq_id(84321, 84316);
  script_osvdb_id(135722, 135723);

  script_name(english:"Apache ActiveMQ 5.x < 5.13.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of ActiveMQ.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache ActiveMQ running on the remote host is 5.x prior
to 5.13.2. It is, therefore, affected by multiple vulnerabilities :

  - A clickjacking vulnerability exists in the web-based
    administration console due to not setting the
    X-Frame-Options header in HTTP responses. A remote
    attacker can exploit this to trick a user into executing
    administrative tasks. (CVE-2016-0734)

  - Multiple cross-site scripting vulnerabilities exists in
    the web-based administration console to improper
    validation of user-supplied input. A remote attacker can
    exploit these, via a specially crafted request, to
    execute arbitrary script code in a user's browser
    session. (CVE-2016-0782)

Note that CVE-2016-0734 was partially fixed in 5.11.4 and 5.12.3 by
setting the X-Frame-Options header for Servlets and JSPs but not
static content. Therefore, the fix for these versions is incomplete,
and it is recommended that users upgrade to 5.13.2 or later.");
  # http://activemq.apache.org/security-advisories.data/CVE-2016-0734-announcement.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d7cdf2a0");
  script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/jira/browse/AMQ-6170");
  script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/jira/browse/AMQ-6113");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache ActiveMQ version 5.13.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/10");
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

fix = '5.13.2';
vuln = FALSE;

if (version =~ "^5\.13\." && ver_compare(ver:version, fix:"5.13.2", strict:FALSE) == -1)
  vuln = TRUE;
else if (version =~ "^5\.12\." && ver_compare(ver:version, fix:"5.12.3", strict:FALSE) <= 0)
  vuln = TRUE;
else if (version =~ "^5\.11\." && ver_compare(ver:version, fix:"5.11.4", strict:FALSE) <= 0)
  vuln = TRUE;
else if (version =~ "^5\.([0-9]|10)(\.|$)")
  vuln = TRUE;

if (!vuln)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);

report =
  '\n  URL               : ' + install_url +
  '\n  Installed version : ' + version +
  '\n  Fixed version     : ' + fix +
  '\n';

security_report_v4(extra:report, port:port, severity:SECURITY_WARNING, xsrf:TRUE);
