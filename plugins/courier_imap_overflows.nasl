#
# (C) Tenable Network Security, Inc.
#

# @DEPRECATED@
#
# Disabled on 2009/10/02. checks if the server is running, but doesn't do an 
# actual version check. too FP prone
exit(0);


if(description)
{
 script_id(12103);
 script_bugtraq_id(9845, 10976);
 script_cve_id("CVE-2004-0224", "CVE-2004-0777");
 script_xref(name:"OSVDB", value:"9013");
 script_xref(name:"OSVDB", value:"6927");
 script_xref(name:"OSVDB", value:"4194");
 script_version("$Revision: 1.14 $");
 
 script_name(english:"Courier IMAP Multiple Remote Vulnerabilities (OF, FS)");

 script_set_attribute(attribute:"synopsis", value:"The remote IMAP service contains multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:"
The remote mail server is the Courier-IMAP imap server.

There is a buffer overflow in the conversions functions of this software
which may allow an attacker to execute arbitrary code on this host."); 

 script_set_attribute(attribute:"solution", value:"Upgrade to Courier-Imap 3.0.0 or newer");
 script_set_attribute(attribute:"cvss_vector", value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
	
 script_summary(english:"Checks the version number"); 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2010 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/imap", 143);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/imap");
if (!  port ) port = 143;

banner = get_kb_item(string("imap/banner/", port));
if(!banner)
 {
  if(get_port_state(port))
  { 
   soc = open_sock_tcp(port);
   if(!soc)exit(0);
   banner = recv_line(socket:soc, length:4096);
   if ( banner ) set_kb_item(name:"imap/banner/" + port, value:banner);
   close(soc);
  }
 }

if(banner)
{
 if ( "OK Courier-IMAP ready." >< banner ) security_hole(port);
}
