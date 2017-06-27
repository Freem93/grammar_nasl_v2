#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(15775);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2004-1536");
  script_bugtraq_id(11719);
  script_osvdb_id(12003);

  script_name(english:"Invision Power Board ibProArcade Module index.php cat Parameter SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a SQL
injection vulnerability." );
 script_set_attribute(attribute:"description", value:
"The installation of Invision Power Board on the remote host includes
an optional module, named 'Arcade', that allows unauthorized users to
inject SQL commands into the remote SQL database through the 'cat'
parameter.  An attacker may use this flaw to gain control of the
remote database and possibly to overwrite files on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Nov/270" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/11/20");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();
 
  script_summary(english:"Detect Invision Power Board Arcade SQL Injection");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencies("invision_power_board_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/invision_power_board");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 path = matches[2];

 w = http_send_recv3(method:"GET",item:string(path, "/index.php?act=Arcade&cat=1'"), port:port);
 if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
 res = w[2];

 if ("mySQL query error: SELECT g.*, c.password FROM ibf_games_list AS" >< res)
 {
  security_hole(port);
   set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
 }
}
