#
# This script was written by Josh Zlatin-Amishav <josh at ramat doti cc>
#
# This script is released under the GNU GPLv2
#
# Changes by Tenable:
# - improved description
# - do a more reliable test (if magic_quotes is on the host is not vulnerable)
# - added references
# - Fixed typo and added CPE

include("compat.inc");

if(description)
{
 script_id(19678);
 script_version ("$Revision: 1.24 $");
 script_cve_id("CVE-2005-2674", "CVE-2005-2675", "CVE-2005-2780");
 script_bugtraq_id(14618, 14619, 14677);
 script_osvdb_id(
   19292, 
   19293, 
   19294, 
   19295, 
   19296, 
   19297, 
   19298
  );

 script_name(english:"Land Down Under <= 800 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that permits SQL injection
and cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The remote version of Land Down Under is prone to various SQL
injection and cross-site scripting attacks provided PHP's
'magic_quotes' setting is disabled due to its failure to sanitize the
request URI before using it in 'system/functions.php' in the function
'ldu_log()'.  A malicious user may be able to exploit this issue to
manipulate SQL queries, steal authentication cookies, and the like. 

In addition, it also fails to properly sanitize the user-supplied
signature in forum posts.  A malicious user can exploit this
vulnerability to steal authentication cookies and manipulate the HTML
format in 'forums.php'." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Aug/275" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Aug/393" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Land Down Under version 801 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/08/21");

 script_cvs_date("$Date: 2016/10/27 15:03:54 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:neocrome:land_down_under");
 script_end_attributes();

 summary["english"] = "Checks for SQL injection in LDU's index.php";

 script_summary(english:summary["english"]);

 script_category(ACT_ATTACK);

 script_family(english:"CGI abuses");
 script_copyright(english:"Copyright (C) 2005-2016 Josh Zlatin-Amishav");

 script_dependencie("ldu_detection.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("www/ldu");
 exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/ldu"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 ver = matches[1];
 dir = matches[2];

 req = http_get(
   item:string(
     dir, "/index.php?",
     "m='", SCRIPT_NAME
   ), 
   port:port
 );
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

 if 
 ( 
   egrep(string:res, pattern:string("MySQL error.+syntax to use near '", SCRIPT_NAME))
 )
 {
        security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
        exit(0);
 }

 # Check the version number in case magic_quotes is enabled.
 if (ver =~ "^([0-7]|800)") {
      desc = string(
          "***** Nessus has determined the vulnerability exists on the remote\n",
          "***** host simply by looking at the version number of Land Down\n",
          "***** Under installed there.\n");
      security_warning(port:port, extra:desc);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
 }
}
