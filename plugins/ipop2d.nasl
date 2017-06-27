#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10130);
 script_version ("$Revision: 1.32 $");
 script_cve_id("CVE-1999-0920");
 script_bugtraq_id(283);
 script_osvdb_id(104);
 
 script_name(english:"IMAP pop-2d POP Daemon FOLD Command Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote IMAP server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"There is a buffer overflow in the imap suite provided with Debian 
GNU/Linux 2.1, which has a vulnerability in its POP-2 daemon, found in
the ipopd package. This vulnerability allows an attacker to gain a 
shell as user 'nobody', but requires the attacker to have a valid pop2
account." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=92774876916776&w=2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to imap-4.5 or later as this reportedly fixes the issue." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/05/26");
 script_cvs_date("$Date: 2011/03/11 21:52:34 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"checks for a buffer overflow in pop2d");
 script_category(ACT_MIXED_ATTACK); # mixed
 script_copyright(english:"This script is Copyright (C) 1999-2011 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_dependencie("find_service1.nasl", "logins.nasl");
 script_require_keys("pop2/password");
 script_require_ports("Services/pop2", 109);
 exit(0);
}

#

port = get_kb_item("Services/pop2");
if(!port)port = 109;

acct = get_kb_item("pop2/login");
pass = get_kb_item("pop2/password");


if((!acct) || (safe_checks()))
{
 banner = get_kb_item(string("pop2/banner/", port));
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
 if(banner)
 {
  if(ereg(pattern:"POP2 .* ((v[0-3]\..*)|(v4\.[0-4].*))",
         string:banner))
	 {
	  alrt = string(
	    "*** Nessus solely relied on banner information\n",
	    "*** to issue this warning.\n",
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
 s1 = string("HELO ",get_host_name(), ":", acct, " ", pass, "\r\n");
 s2 = string("FOLD ", crap(1024), "\r\n");
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
 c = recv_line(socket:soc, length:1024);
 if(strlen(c) == 0)security_hole(port);
 close(soc);
}

