#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11654);
 script_version ("$Revision: 1.10 $");
 script_bugtraq_id(7658);
 script_osvdb_id(57631);
 
 script_name(english:"ShareMailPro POP3 Interface Error Message Account Enumeration");
	     
 script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to information disclosure." );
 script_set_attribute(attribute:"description", value:
"The remote ShareMail server issues a special error message
when a user attempts to log in using a nonexistent POP
account.

An attacker may use this flaw to make a list of valid accounts
by looking at the error messages it receives at authentication
time." );
 script_set_attribute(attribute:"solution", value:
"None at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/27");
 script_cvs_date("$Date: 2011/03/11 21:52:38 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks for the pop login error");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.");
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/pop3", 110);
 exit(0);
}

#
# The script code starts here : 
#


port = get_kb_item("Services/pop3");
if(!port)port = 110;

state = get_port_state(port);
if(!state)exit(0);
soc = open_sock_tcp(port);
if(soc)
{
 banner = recv_line(socket:soc, length:4096);
 if(!banner)exit(0);
 send(socket:soc, data:string("USER nessus", rand(), rand(), "\r\n"));
 r = recv_line(socket:soc, length:4096);
 if(!r)exit(0);
 if("-ERR sorry" >< r) { security_warning(port); }
}
