#
# This script was written by David Kyger <david_kyger@symantec.com>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, added CVE/OSVDB, added solution, output formatting (9/3/09)


include("compat.inc");

if(description)
{
  script_id(12119);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/01/25 01:19:09 $");
  script_cve_id("CVE-2000-1210");
  script_osvdb_id(7203);

  script_name(english:"Novell NetWare 6.0 Tomcat source.jsp Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"Sensitive data can be read on the remote data." );
 script_set_attribute(attribute:"description", value:
"The Apache Tomcat server distributed with NetWare 6.0 has a directory 
traversal vulnerability. As a result, sensitive information 
could be obtained from the NetWare server, such as the RCONSOLE 
password located in AUTOEXEC.NCF.

Example : 

http://target/examples/jsp/source.jsp?%2e%2e/%2e%2e/%2e%2e/%2e%2e/system/autoexec.ncf" );
 script_set_attribute(attribute:"solution", value:
"Upgrade Tomcat to the latest version, or disable the service
if it is not required.
Remove default files from the web server. Also, ensure the RCONSOLE 
password is encrypted and utilize a password protected screensaver for 
console access." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/03/30");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/03/21");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/o:novell:netware");
script_set_attribute(attribute:"cpe",value:"cpe:/a:apache:tomcat");
script_end_attributes();

 script_summary(english:"Checks for the NetWare 6.0 Tomcat source code viewer vulnerability");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2013 David Kyger");
 script_family(english:"Netware");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

warning = "The content of the AUTOEXEC.NCF follows:";

url = "/examples/jsp/source.jsp?%2e%2e/%2e%2e/%2e%2e/%2e%2e/system/autoexec.ncf";
 
port = get_http_port(default:80);

if(get_port_state(port))
 {
   req = http_get(item:url, port:port);
   buf = http_keepalive_send_recv(port:port, data:req);
   if ("SYS:\" >< buf)
    {
     warning = warning + '\n'+ buf + '\n';
     security_hole(port:port, extra:warning);
    }
 }


