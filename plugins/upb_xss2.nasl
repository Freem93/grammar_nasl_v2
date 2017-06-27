#
# This script was written by Josh Zlatin-Amishav <josh at ramat dot cc>
#
# This script is released under the GNU GPLv2

# Changes by Tenable:
# - Revised plugin title (4/9/2009)

include("compat.inc");

if (description)
{
  script_id(19499);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/01/15 03:38:17 $");

  script_bugtraq_id(14348, 14350);
  script_osvdb_id(18143, 18144, 18145, 18146, 18147);

  script_name(english:"Ultimate PHP Board 1.9.6 GOLD Multiple Scripts XSS (1)");
  script_summary(english:"Checks for XSS in send.php");

  script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host has multiple cross-site scripting
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Ultimate PHP Board (UPB). This version of
UPB has multiple cross-site scripting vulnerabilities. A remote
attacker could exploit these issues by tricking a user into requesting
a maliciously crafted URL, resulting in the execution of arbitrary
script code.");
  script_set_attribute(attribute:"see_also", value:"http://www.retrogod.altervista.org/upbgold196xssurlspoc.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/402461");
  script_set_attribute(attribute:"see_also", value:"http://www.retrogod.altervista.org/upbgold196poc.php.txt");
  script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
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
xss = "<script>alert(" + SCRIPT_NAME + ")</script>";
# nb: the url-encoded version is what we need to pass in.
exss = urlencode(str:xss);

foreach dir ( cgi_dirs() )
{
 req = http_get(
   item:string(
     dir, "/chat/send.php?css=",
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
