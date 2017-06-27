#
# This script was written by Josh Zlatin-Amishav <josh at ramat dot cc>
#
# This script is released under the GNU GPLv2

include("compat.inc");

if (description)
{
  script_id(19498);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/01/15 03:38:17 $");

  script_cve_id("CVE-2005-2004");
  script_bugtraq_id(13971);
  script_osvdb_id(
    17365,
    17366,
    17367,
    17368,
    17369,
    17370,
    17371,
    17372,
    17373
  );

  script_name(english:"Ultimate PHP Board 1.9.6 GOLD Multiple Scripts XSS (2)");
  script_summary(english:"Checks for XSS in login.php");

  script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host has multiple cross-site scripting
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Ultimate PHP Board (UPB). The remote
version of this software is affected by several cross-site scripting
vulnerabilities. These issues are due to a failure of the application
to properly sanitize user-supplied input.");
  script_set_attribute(attribute:"see_also", value:"http://securityfocus.com/archive/1/402461");
  script_set_attribute(attribute:"see_also", value:"http://www.myupb.com/forum/viewtopic.php?id=26&t_id=118");
  script_set_attribute(attribute:"solution", value:"Upgrade to UPB 2.2.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ultimate_php_board:ultimate_php_board");

  script_end_attributes();

  script_category(ACT_ATTACK);

  script_family(english:"CGI abuses : XSS");
  script_copyright(english:"Copyright (C) 2005-2015 Josh Zlatin-Amishav");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("Settings/ParanoidReport", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);
if ( get_kb_item("www/"+port+"/generic_xss") ) exit(0);

# A simple alert.
xss = "'><script>alert(" + SCRIPT_NAME + ")</script>";
# nb: the url-encoded version is what we need to pass in.
exss = urlencode(str:xss);

foreach dir ( cgi_dirs() )
{
 req = http_get(
   item:string(
     dir, "/login.php?ref=",
     exss
   ),
   port:port
 );


 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

 if ( xss >< res )
 {
        security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
        exit(0);
 }
}
