#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10197);
 script_version("$Revision: 1.30 $");
 script_cvs_date("$Date: 2014/05/26 15:47:04 $");

 script_cve_id("CVE-2000-0096");
 script_bugtraq_id(948);
 script_osvdb_id(12483);

 script_name(english:"Qpopper < 3.0.2 LIST Command Local Overflow");
 script_summary(english:"checks for a buffer overflow in pop3");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code may be run on the remote server.");
 script_set_attribute(attribute:"description", value:
"There is a vulnerability in the Qpopper 3.0b package that allows users
with a valid account to gain a shell on the system");
 script_set_attribute(attribute:"solution", value:"Upgrade to version 3.0.2 or newer");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/01/26");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/01/27");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2000-2014 Tenable Network Security, Inc.");
 script_family(english:"Misc.");

 script_dependencie("popserver_detect.nasl", "logins.nasl");
 script_require_keys("pop3/login", "pop3/password", "Settings/ParanoidReport");
 script_require_ports("Services/pop3", 110);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

acct = get_kb_item("pop3/login");
pass = get_kb_item("pop3/password");

if((acct == "")||(pass == ""))exit(0);

port = get_kb_item("Services/pop3");
if(!port)port = 110;

if(get_port_state(port))
{
 s1 = string("USER ", acct, "\r\n");
 s2 = string("PASS ", pass, "\r\n");

 s3 = string("LIST 1 ", crap(4096), "\r\n");

 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 b = recv_line(socket:soc, length:1024);
 if(!strlen(b)){
 	close(soc);
	exit(0);
	}
 send(socket:soc, data:s1);
 b = recv_line(socket:soc, length:1024);
 send(socket:soc, data:s2);
 b = recv_line(socket:soc, length:1024);
 if("OK" >< b)
 {
  send(socket:soc, data:s3);
  c = recv_line(socket:soc, length:1024);
  if(strlen(c) == 0)security_warning(port);
 }
 close(soc);
}

