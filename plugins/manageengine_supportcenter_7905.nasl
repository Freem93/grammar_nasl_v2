#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(58976);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/02/11 21:07:49 $");

  script_bugtraq_id(53019);
  script_osvdb_id(81155, 81156, 81157, 81158, 81159, 81160);
  script_xref(name:"EDB-ID", value:"18745");

  script_name(english:"ManageEngine SupportCenter Plus < 7.9 Build 7905 Multiple Vulnerabilities");
  script_summary(english:"Checks version of ManageEngine SupportCenter Plus");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is running a web application affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a version of ManageEngine SupportCenter
Plus less than 7.9 build 7905.  Such versions are affected by multiple
vulnerabilities:

  - A SQL injection vulnerability in the 'countSql' 
    parameter of the '/servlet/AJaxServlet' script.

  - Multiple stored cross-site scripting vulnerabilities 
    that can be exploited by both authenticated and 
    anonymous users.

  - A vulnerability that allows any authenticated user to 
    delete SupportCenter backups.

  - A vulnerability that allows any authenticated user to 
    schedule and write a backup file to a publicly 
    accessible directory."
  );
  script_set_attribute(attribute:"see_also", value:"https://supportcenter.wiki.zoho.com/ReadMe-V2.html#7905");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to ManageEngine SupportCenter version 7.9 build 7905 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:manageengine:supportcenter_plus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("manageengine_supportcenter_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/manageengine_supportcenter");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");

port = get_http_port(default:8080);
appname = 'ManageEngine SupportCenter Plus';

install = get_install_from_kb(appname:'manageengine_supportcenter', port:port, exit_on_fail:TRUE);
dir = install['dir'];
install_url = build_url(qs:dir, port:port);
ver_ui = install['ver'];

item = eregmatch(pattern: "^([0-9\.]+) Build ([0-9]+)$", string: ver_ui);
if(isnull(item)) exit(1, "Failed to parse the version string of the "+appname+" install at "+install_url+".");

build = int(item[2]);

ver = split(item[1], sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if(ver[0] < 7 ||
  (ver[0] == 7 && ver[1] < 9) ||
  (ver[0] == 7 && ver[1] == 9 && ver[2] == 0 && build < 7905))
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  
  if(report_verbosity > 0) 
  {
    report = '\n  URL               : ' + install_url +
             '\n  Installed version : ' + ver_ui + 
             '\n  Fixed version     : 7.9.0 Build 7905\n';
    security_warning(port:port, extra:report);
  } 
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, ver_ui);
