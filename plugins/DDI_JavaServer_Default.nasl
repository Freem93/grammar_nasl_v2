#
# This script written by H D Moore <hdmoore@digitaldefense.net>
#
# See the Nessus Scripts License for details
#

include("compat.inc");

if(description)
{
 script_id(10995);
 script_version("$Revision: 1.13 $");
 script_cvs_date("$Date: 2012/08/15 21:05:11 $");

 script_cve_id("CVE-1999-0508");
 script_osvdb_id(817);

 script_name(english:"Sun JavaServer Default Admin Password");
 script_summary(english:"Sun JavaServer Default Admin Password");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a default set of administrative
credentials.");
 script_set_attribute(attribute:"description", value:
"The remote host is running the Sun JavaServer.  This server has the
default username and password of admin.  An attacker can use this to
gain complete control over the web server configuration and possibly
execute commands.");
 script_set_attribute(attribute:"solution", value:
"Set the web administration interface to require a password.  For more
information please consult the documentation located in the /system/
directory of the web server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SNMP Community Scanner');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value:
"2002/06/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/09/12");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2002-2012 Digital Defense Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 9090);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("misc_func.inc");

req = NULL;
req = "/servlet/admin?category=server&method=listAll&Authorization=Digest+";
req = req + "username%3D%22admin%22%2C+response%3D%22ae9f86d6beaa3f9ecb9a5b7e072a4138%22%2C+";
req = req + "nonce%3D%222b089ba7985a883ab2eddcd3539a6c94%22%2C+realm%3D%22adminRealm%22%2C+";
req = req + "uri%3D%22%2Fservlet%2Fadmin%22&service=";

ports = add_port_in_list(list:get_kb_list("Services/www"), port:9090);

foreach port (ports)
{
    if ( ! get_kb_item("Services/www/" + port + "/embedded") )
    {
    soc = http_open_socket(port);
    if (soc)
    {
        req1 = NULL;
        req1 = string("GET ", req, " HTTP/1.0\r\n\r\n");
        send(socket:soc, data:req1);
        buf = http_recv(socket:soc);
        http_close_socket(soc);
        if (!isnull(buf) && "server.javawebserver.serviceAdmin" >< buf)
        {
            security_hole(port:port);
        }
    }
  }
}
