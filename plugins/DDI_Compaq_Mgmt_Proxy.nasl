#
# Written by H D Moore <hdmoore@digitaldefense.net>
#
# Changes by Tenable:
# - Revised plugin title, changed family, added OSVDB ref (1/21/2009)


include("compat.inc");

if(description)
{
 script_id(10963);
 script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2013/11/04 22:14:20 $");

 script_cve_id("CVE-2001-0374");
 script_osvdb_id(787);

 script_name(english:"Compaq Web-enabled Management Software HTTP Server Arbitrary Traffic Proxy");
 script_summary(english:"Compaq Web-Based Management Agent Proxy Vulnerability");

 script_set_attribute(attribute:"synopsis", value:
"The remote web management agent can be abused to serve as a network
proxy." );
 script_set_attribute(attribute:"description", value:
"The remote Compaq Web Management Agent install can be used as an HTTP
proxy.  An attacker can use this to bypass firewall rules or hide the
source of web-based attacks." );
 script_set_attribute(attribute:"see_also", value:
"http://h18000.www1.hp.com/products/servers/management/SSRT0758.html" );
 script_set_attribute(attribute:"solution", value:
"Due to the information leak associated with this service, you should
disable the Compaq Management Agent or filter access to TCP ports 2301
and 280. 

If this service is required, contact the vendor for a software
update." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value:
"2002/05/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/01/09");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2002-2013 Digital Defense Inc.");
 script_family(english:"Web Servers");

 script_dependencie("find_service1.nasl", "http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 2301);
 script_require_keys("www/compaq");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");
include("misc_func.inc");

ports = add_port_in_list(list:get_kb_list("Services/www"), port:2301);

foreach port (ports)
{
    soc = http_open_socket(port);
    if (soc)
    {
        req = string("GET http://127.0.0.1:2301/ HTTP/1.0\r\n\r\n");
        send(socket:soc, data:req);
        buf = http_recv(socket:soc);
        http_close_socket(soc);
        
        if (!isnull(buf) && "Compaq WBEM Device Home" >< buf)
        {
            security_hole(port);
        }
    }
}
