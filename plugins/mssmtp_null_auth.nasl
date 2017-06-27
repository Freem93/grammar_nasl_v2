#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11308);
 script_version("$Revision: 1.26 $");
 script_cvs_date("$Date: 2013/11/04 02:28:18 $");

 script_cve_id("CVE-2002-0054");
 script_bugtraq_id(4205);
 script_osvdb_id(5390, 10247);
 script_xref(name:"MSFT", value:"MS02-011");

 script_name(english:"Microsoft Windows SMTP Service NTLM Null Session Authorization Bypass (uncredentialed check)");
 script_summary(english:"Checks SMTP authentication");

 script_set_attribute(attribute:"synopsis", value:
"The remote SMTP server is affected by an authorization bypass
vulnerability." );
 script_set_attribute(attribute:"description", value:
"It is possible to authenticate to the remote SMTP service by logging
in with a NULL session.

An attacker may use this flaw to use your SMTP server as a spam relay." );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms02-011");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released patches for Windows NT and 2000 as well as
Exchange Server 5.5.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/02");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2003-2013 Tenable Network Security, Inc.");
 script_family(english:"SMTP problems");

 script_dependencie("smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");
include("smtp_func.inc");

port = get_service(svc:"smtp", default: 25, exit_on_fail: 1);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 data = smtp_recv_banner(socket:soc);
 if ( ! data ||  "Microsoft" >!< data  ) exit(0);
 crp = string("HELO example.com\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 if(!(ereg(pattern:"^250 .*", string:data)))exit(0);

 send(socket:soc, data:string("AUTH NTLM TlRMTVNTUAABAAAAB4IAgAAAAAAAAAAAAAAAAAAAAAA=\r\n"));
 r = recv_line(socket:soc, length:4096);
 if(!ereg(string:r, pattern:"^334 .*"))exit(0);
 send(socket:soc, data:string("TlRMTVNTUAADAAAAAQABAEAAAAAAAAAAQQAAAAAAAABAAAAAAAAAAEAAAAAAAAAAQAAAAAAAAABBAAAABYIAAAA=\r\n"));
 r = recv_line(socket:soc, length:4096);
 if(ereg(string:r, pattern:"^235 .*"))security_warning(port);
}
