#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10625);
 script_version ("$Revision: 1.27 $");
 script_cve_id("CVE-2000-0284");
 script_bugtraq_id(1110);
 script_osvdb_id(12037);
 
 script_name(english:"UoW imapd (UW-IMAP) Multiple Command Remote Overflows");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote IMAP server is affected by multiple remote buffer overflow
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running UoW IMAP Server. The installed
version is affected by a buffer overflow vulnerability because the 
software fails to verify input length of arguments to the 'LIST', 
'COPY', 'RENAME', 'FIND', 'LSUB' commands. An attacker, exploiting 
this flaw could execute arbitrary commands subject to the privileges
of the connected user." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Apr/63" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Apr/74" );
 script_set_attribute(attribute:"see_also", value:"http://packetstormsecurity.org/0104-exploits/imap-lsub.pl" );
 script_set_attribute(attribute:"see_also", value:"http://www.ca.com/us/securityadvisor/vulninfo/vuln.aspx?id=2442" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to imap-2000 or higher, as this reportedly fixes the issue." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'UoW IMAP Server LSUB Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"plugin_publication_date", value: "2001/03/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/04/16");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"checks for a buffer overflow in imapd");
 script_category(ACT_MIXED_ATTACK); # mixed
 script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_dependencie("find_service1.nasl", "logins.nasl");
		       		     
 script_require_ports("Services/imap", 143);
 script_exclude_keys("imap/false_imap");
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/imap");
if(!port)port = 143;


acct = get_kb_item("imap/login");
pass = get_kb_item("imap/password");

if((!pass) ||
   (safe_checks()))
{
 banner = get_kb_item(string("imap/banner/", port));
 if(!banner)
 {
  if(get_port_state(port))
  {
   soc = open_sock_tcp(port);
   if(!soc)exit(0);
   banner = recv_line(socket:soc, length:4096);
   close(soc);
  }
 }
 
 if("IMAP4rev" >< banner)
 {
  if(ereg(pattern:".*IMAP4rev.* v12\.([0-1].*|2([0-5].*|6[0-4]))",
  	  string:banner))
	  {
	   alrt = string(
	     "\n",
             "*** Nessus solely relied on the server banner to \n",
             "*** issue this warning.\n",
             "\n"
           );
	security_hole(port:port, extra:alrt);
	  }
 }
 exit(0);
}

if((acct == "")||(pass == ""))exit(0);


if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 b = recv_line(socket:soc, length:1024);
 if(!strlen(b)){
 	close(soc);
	exit(0);
	}
 s1 = string("1 login ", acct, " ", pass, "\r\n");	
 send(socket:soc, data:s1);
 b = recv_line(socket:soc, length:1024);
 
 s2 = string("1 lsub ", raw_string(0x22, 0x22), " {1064}\r\n");
 send(socket:soc, data:s2);
 c = recv_line(socket:soc, length:1024);
 s3 = string(crap(1064), "\r\n");
 send(socket:soc, data:s3);
 
 c = recv_line(socket:soc, length:1024);
 if(strlen(c) == 0)security_hole(port);
 close(soc);
}

