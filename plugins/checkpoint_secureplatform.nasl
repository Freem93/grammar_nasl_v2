#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(17584);
 script_version("$Revision: 1.9 $");
 script_cvs_date("$Date: 2012/10/16 21:55:42 $");
 
 script_name(english:"Check Point Secure Platform Detection");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to connect to the remote Check Point system." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be a Check Point Secure Platform, and it
allows connections to its web console management. 

Letting attackers know that you are using this software will help them
focus their attack or make them change their strategy.  In addition to
this, an attacker may attempt to launch a brute-force attack to log
into the remote interface." );
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port." );
 script_set_attribute(attribute:"risk_factor", value:
"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/21");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:checkpoint:secure_platform_ng");
script_end_attributes();

 
 script_summary(english:"Check Point Secure Platform web console management");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_dependencie("http_version.nasl");

 script_require_ports(443);
 exit(0);
}

function https_get(port, request)
{
    local_var result, soc;

    if(get_port_state(port))
    {

         soc = open_sock_tcp(port, transport:ENCAPS_SSLv23);
         if(soc)
         {
            send(socket:soc, data:string(request,"\r\n"));
            result = http_recv(socket:soc);
            close(soc);
            return(result);
         }
    }
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = 443;
if(get_port_state(port))
{
 req = http_get(item:"/deploymentmanager/index.jsp", port:port);
 rep = https_get(request:req, port:port);
 if( rep == NULL ) exit(0);
 #<title>SecurePlatform NG with Application Intelligence (R55) </title>
 if ("<title>SecurePlatform NG with Application Intelligence " >< rep)
 {
   security_note(port);
 }
}
