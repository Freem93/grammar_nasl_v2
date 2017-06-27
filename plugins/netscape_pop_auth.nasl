#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10681);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-2000-0960");
 script_bugtraq_id(1787);
 script_osvdb_id(565);

 script_name(english:"Netscape Messenging Server POP3 Error Message User Account Enumeration");

 script_set_attribute(attribute:"synopsis", value:
"The remote POP server allows an attacker to determine whether
a given username exists or not." );
 script_set_attribute(attribute:"description", value:
"The remote POP server allows an attacker to obtain a list
of valid logins on the remote host, thanks to a brute-force
attack.

If the user connects to this port and issues the commands :
USER 'someusername'
PASS 'whatever'

the user will then get a different response whether the account
'someusername' exists or not." );
 script_set_attribute(attribute:"solution", value:
"None at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/05/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/10/11");
 script_cvs_date("$Date: 2015/12/23 21:38:31 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:netscape:messaging_server");
script_end_attributes();

 script_summary(english:"Checks the error messages issued by the pop3 server");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2015 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_dependencie("find_service1.nasl");
 script_exclude_keys("global_settings/supplied_logins_only");
 script_require_ports("Services/pop3", 110);
 exit(0);
}

#
# The script code starts here
#

include("audit.inc");
include("global_settings.inc");
include("pop3_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_kb_item("Services/pop3");
if (!port) port = 110;
banner =  get_pop3_banner(port:port);
if ( ! banner || "Netscape Messaging Server" >!< banner ) exit(0);

if (get_port_state(port))
{
 soc = open_sock_tcp(port);

 if (soc)
 {
  r = recv_line(socket:soc, length:4096);
  if(r)
  {
   send(socket:soc, data:string("USER nessus", rand(), "\r\n"));
   r = recv_line(socket:soc, length:4096);
   send(socket:soc, data:string("PASS nessus", rand(), "\r\n"));
   r = recv_line(socket:soc, length:4096);
   close(soc);
   if(r && "User unknown" >< r)security_warning(port);
  }
 }
}
