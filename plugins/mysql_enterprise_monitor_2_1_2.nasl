#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46816);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/01/30 19:28:01 $");

  script_bugtraq_id(40537);
  script_osvdb_id(65085);

  script_name(english:"MySQL Enterprise Monitor < 2.1.2 Multiple XSRF Vulnerabilities");
  script_summary(english:"Checks the version of MySQL Enterprise Monitor.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by multiple
cross-site request forgery vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the MySQL Enterprise Monitor
running on the remote host has multiple, unspecified cross-site
request forgery vulnerabilities. A remote attacker can exploit these
by tricking a user into unknowingly performing malicious actions.");
  # https://docs.oracle.com/cd/E19957-01/mysql-monitor-2.1/mysql-monitor-2.1.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fb1c1be");
  # http://web.archive.org/web/20101108045230/http://dev.mysql.com/doc/refman/5.1/en/mem-news-2-1-2.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7090189d");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL Enterprise Monitor 2.1.2 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:mysql:enterprise_monitor");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_dependencies("mysql_enterprise_monitor_web_detect.nasl");
  script_require_keys("installed_sw/MySQL Enterprise Monitor");
  script_require_ports("Services/www", 18080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app  = "MySQL Enterprise Monitor";
get_install_count(app_name:app, exit_if_zero:TRUE);

fix  = "2.1.2";
port = get_http_port(default:18080);

install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);
version = install['version'];
install_url = build_url(port:port, qs:"/");

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);
    
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
