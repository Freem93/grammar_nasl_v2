#
# This script was written by Josh Zlatin-Amishav <josh at tkos dot co dot il>
#
# This script is released under the GNU GPLv2
#

# Changes by Tenable:
# - Revised plugin title, added CVE/OSVDB, changed family (4/7/2009)
# - Updated to use compat.inc, Added CVSS score (11/18/2009)


include("compat.inc");

if(description)
{
 script_id(18265);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2005-1620");
 script_bugtraq_id(13632);
 script_osvdb_id(16613);

 script_name(english:"Skull-Splitter Guestbook Multiple Field XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running the Skull-Splitter guestbook, a guestbook
written in PHP." );
 script_set_attribute(attribute:"description", value:
"The remote version of this software is vulnerable to cross-site
scripting attacks. Inserting special characters into the subject
or message content can cause arbitrary script code execution for 
third-party users, thus resulting in a loss of integrity of their 
system." );
 script_set_attribute(attribute:"solution", value:
"None at this time" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/14");
 script_cvs_date("$Date: 2015/01/23 22:03:56 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 script_summary(english:"Skull-Splitter Guestbook Multiple HTML Injection Vulnerabilities");

 script_category(ACT_GATHER_INFO);

 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"Copyright (C) 2005-2015 Josh Zlatin-Amishav");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

function check(url)
{
 local_var req, res;
 req = http_get(item:url +"/guestbook.php", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);

 if ( egrep(pattern:"Powered by.*Skull-Splitter's PHP Guestbook ([0-1]\..*|2\.[0-2][^0-9])", string:res) )
 {
     security_warning(port);
     set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
     exit(0);
 }
}

foreach dir ( make_list (cgi_dirs(), "/guestbook") )
{
  check(url:dir);
}
