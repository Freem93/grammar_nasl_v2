#
# This script was written by Josh Zlatin-Amishav <josh at tkos dot co dot il>
#
# This script is released under the GNU GPLv2
#

# Changes by Tenable:
# - Revised plugin title (4/28/09)
# - Revised script summary (9/6/11)
# - Re-aligned OSVDBs, revised description and added URL comment and CPE (11/29/12)

include("compat.inc");

if(description)
{
 script_id(18375);
 script_version ("$Revision: 1.20 $");

 script_cve_id("CVE-2005-1782", "CVE-2005-1783");
 script_bugtraq_id(13783);
 script_osvdb_id(
   16871,
   16872,
   16873,
   16874,
   16875,
   16876,
   16877,
   16878,
   16879,
   16880,
   16881
 );

 script_name(english:"BookReview 1.0 Multiple Script XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI that is vulnerable to multiple
cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the BookReview software. 

The remote version of this software is vulnerable to multiple
cross-site scripting attacks due to a lack of sanitization of
user-supplied data. 

Successful exploitation of this issue may allow an attacker to use the
remote server to perform an attack against a third-party user." );
  # http://lostmon.blogspot.com/2005/05/bookreview-10-multiple-variable-xss.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4a2658c9" );
 script_set_attribute(attribute:"solution", value:
"None at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/27");
 script_cvs_date("$Date: 2015/01/13 20:37:05 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:w.m.r._simpson:bookreview");
script_end_attributes();


 script_summary(english:"Checks for unauthenticated access to admin.asp");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"Copyright (C) 2005-2015 Josh Zlatin-Amishav");
 script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

global_var port;

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if (  get_kb_item(string("www/", port, "/generic_xss")) ) exit(0);

function check(url)
{
 local_var req, res;

 req = http_get(item:url +"/add_url.htm?node=%3Cscript%3Ealert('XSS')%3C/script%3E", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if ( "<script>alert('XSS')</script>XSS" >< res && 'Powered by BookReview' >< res )
 {
        security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
        exit(0);
 }
}

foreach dir ( cgi_dirs() )
  check(url:dir);
