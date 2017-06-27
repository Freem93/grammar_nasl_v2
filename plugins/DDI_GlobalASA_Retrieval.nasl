#
# This script was written by H D Moore
# 
# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (1/08/2009)


include("compat.inc");

if(description)
{
    script_id(10991);
    script_version ("$Revision: 1.20 $");
    script_cvs_date("$Date: 2015/10/21 20:34:20 $");

    # script_cve_id("CVE-MAP-NOMATCH");
    script_osvdb_id(814);
    # NOTE: reviewed, and no CVE id currently assigned (jfs, december 2003)

    script_name(english: "Microsoft IIS global.asa Remote Information Disclosure");
    script_summary(english: "Tries to retrieve the global.asa file");

    script_set_attribute(attribute:"synopsis", value:
"The remote web server leaks sensitive information." );
    script_set_attribute(attribute:"description", value:
"This host is running the Microsoft IIS web server.  This web server
contains a configuration flaw that allows the retrieval of the
global.asa file. 

This file may contain sensitive information such as database
passwords, internal addresses, and web application configuration
options.  This vulnerability may be caused by a missing ISAPI map of
the .asa extension to asp.dll." );
 script_set_attribute(attribute:"solution", value:

"To restore the .asa map :

  - Open Internet Services Manager. 

  - Right-click on the affected web server and choose 
    Properties from the context menu. 

  - Select Master Properties, then Select WWW Service --> 
    Edit --> Home Directory --> Configuration. 

  - Click the Add button

  - Specify C:\winnt\system32\inetsrv\asp.dll as the 
    executable (may be different depending on your 
    installation), 

  - Enter .asa as the extension, 

  - Limit the verbs to GET,HEAD,POST,TRACE, 

  - Ensure the Script Engine box is checked and 

  - Click OK." );
    script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:P");
    script_set_attribute(attribute:"plugin_publication_date", value:
"2002/06/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/12/01");
    script_set_attribute(attribute:"plugin_type", value:"remote");
    script_end_attributes();

    script_category(ACT_ATTACK);
    script_copyright(english:"This script is Copyright (C) 2001-2015 Digital Defense Inc.");
    script_family(english: "CGI abuses");
    script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
    script_require_ports("Services/www", 80);
    exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port)){ exit(0); }
sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);

function sendrequest (request, port)
{
    return http_keepalive_send_recv(port:port, data:request); 	 
} 	 
	  	 
req = http_get(item:"/global.asa", port:port); 	 
reply = sendrequest(request:req, port:port); 	 
if ("RUNAT" >< reply)
{
    security_note(port:port);
    set_kb_item(name:"iis/global.asa.download", value:TRUE);
}
