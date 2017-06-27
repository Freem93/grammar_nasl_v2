#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10123);
 script_version ("$Revision: 1.31 $");
 script_cve_id("CVE-1999-1557");
 script_bugtraq_id(502);
 script_osvdb_id(10842);

 script_name(english:"IMail IMAP Server Login Functions Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote IMAP server is affected by a buffer overflow
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running IMail IMAP server. The installed version
is affected by a buffer overflow when handling a long user name, or a
long password. An attacker, exploiting this flaw, could cause a denial
of service, or possibly execute arbitrary code subject to the
permissions of the IMAP server." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=92038879607336&w=2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to IMail 5.0.3 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/03/01");
 script_cvs_date("$Date: 2014/07/14 21:05:21 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"IMail's imap buffer overflow"); 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 1999-2014 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_dependencie("find_service1.nasl", "imap_overflow.nasl");
 script_exclude_keys("imap/false_imap", "imap/overflow");
 script_require_ports("Services/imap", 143);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc: "imap", default:143, exit_on_fail: 1);
if (get_kb_item("imap/"+port+"/overflow")) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(1, "Cannot connect to TCP port "+port+".");

  buf = recv_line(socket:soc, length:1024);
  if ( "imail" >!< tolower(buf) ) exit(0);
 if(!strlen(buf))
 	{ 
	 	close(soc);
		exit(0);
	}
data = string("X LOGIN ", crap(1200), " ", crap(1300), "\r\n");
send(socket:soc, data:data);
  buf = recv_line(socket:soc, length:1024);
  if(!strlen(buf)){
  	security_hole(port);
	set_kb_item(name:"imap/overflow_imail", value:TRUE);
	set_kb_item(name:"imap/"+port+"/overflow_imail", value:TRUE);
	}
  close(soc);
