#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(17599);
 script_version("$Revision: 1.12 $");

 script_cve_id("CVE-2005-0861");
 script_bugtraq_id(12867);
 script_osvdb_id(14915);

 script_name(english:"DeleGate < 8.11 Multiple Unspecified Overflows");
 script_summary(english:"Checks version in DeleGate's banner"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote proxy server is affected by multiple buffer overflow
issues.");
 script_set_attribute(attribute:"description", value:
"The remote host is running DeleGate, a multi-application proxy. 

According to its banner, the installed version of DeleGate contains
multiple unspecified 'overflows on arrays', which could lead to
arbitrary code execution subject to the privileges under which the
application operates.");
 script_set_attribute(attribute:"see_also", value:
"http://www.delegate.org/mail-lists/delegate-en/2793");
 script_set_attribute(attribute:"see_also", value:
"http://www.delegate.org/mail-lists/delegate-en/2840");
 script_set_attribute(attribute:"solution", value:
"Upgrade to DeleGate version 8.11 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value:
"2005/03/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/03/15");
 script_cvs_date("$Date: 2011/11/28 21:39:45 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 script_family(english:"Firewalls"); 
 script_dependencie("http_version.nasl","find_service1.nasl");
 script_require_ports("Services/http_proxy", 8080, "Services/pop3", 110);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("pop3_func.inc");


port = get_kb_item("Services/pop3");
if ( ! port ) port = 110;
if ( get_port_state(port) )
{
 banner = get_pop3_banner(port:port);
 if ( banner )
 {
  if ( egrep(pattern:"^\+OK Proxy-POP server \(Delegate/([0-7]\..*|8\.([0-9]\..*|10\..)) by", string:banner) )
	security_hole(port);
  exit(0);
 }
}

port = get_kb_item("Services/http_proxy");
if(!port) port = 8080;

if(get_port_state(port))
{
   banner = get_http_banner(port:port);
   if ( banner )
   {
   #Server: DeleGate/8.11.1
   serv = strstr(banner, "Server");
   if(ereg(pattern:"^Server:.*DeleGate/([0-7]\.|8\.([0-9]\.|10\.))", string:serv, icase:TRUE))
     security_hole(port);
   }
}
