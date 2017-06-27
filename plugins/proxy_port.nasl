#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10193);
 script_version ("$Revision: 1.28 $");
 script_cvs_date("$Date: 2013/01/25 01:19:09 $");
 script_name(english:"HTTP Proxy Arbitrary Site/Port Relaying");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote proxy can be used to connect to arbitrary ports" );
 script_set_attribute(attribute:"description", value:
"The remote proxy, allows everyone to perform requests against 
arbitrary ports, such as :

'GET http://cvs.nessus.org:110'. 

This problem may allow attackers to go through your firewall, 
by connecting to sensitive ports like 25 (sendmail) using the 
proxy. In addition to that, it might be used to perform attacks 
against other networks." );
 script_set_attribute(attribute:"solution", value:
"Set up ACLs in place to prevent your proxy from accepting to
connect to non-authorized ports." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/22");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Determines if we can use the remote web proxy against any port");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2013 Tenable Network Security, Inc.");
 script_family(english:"Firewalls");
 script_dependencie("find_service1.nasl", "proxy_use.nasl");
 script_require_keys("Proxy/usage");
 script_require_ports("Services/http_proxy", 8080);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_kb_item("Services/http_proxy");
if(!port) port = 8080;
usable_proxy = get_kb_item("Proxy/usage");
if (! usable_proxy) exit(0);

if (! get_port_state(port)) exit(0);

rq = http_mk_proxy_request(scheme:"http", host: get_host_name(), port: 25, method:"GET", item:"/");
r1 = http_send_recv_req(port: port, req: rq);
if (isnull(r1)) exit(0, "The remote proxy did not answer");
if(" 503" >< r1[0])
{
  security_warning(port);
  exit(0);
}
else
{
  if(" 200" >< r1[0])
  {
    #
    # Some stupid servers reply with a 200- code 
    # to say that an error occured...
    #
    rq = http_mk_proxy_request(scheme:"http", host: get_host_name(), port: 26, method:"GET", item:"/"); 
    r2 = http_send_recv_req(port: port, req: rq);
    if( " 503" >< r2[0])
    {
      security_warning(port);
      exit(0);
    }
    else
    {
      if (" 200" >< r2[0])
      {
        if (r1[2] == r2[2]) exit(0);
	else
	  security_warning(port);
      }
    }
  }
}
