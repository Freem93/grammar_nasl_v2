# Script Written By Ferdy Riphagen 
# <f[dot]riphagen[at]nsec[dot]nl>
#
# Script distributed under the GNU GPLv2 License.
#

# Changes by Tenable:
# - Revised plugin title (8/5/09)
# - Changed plugin family (8/17/09)


include("compat.inc");

if (description) {
 script_id(21116);
 script_version("$Revision: 1.16 $");

 script_cve_id("CVE-2006-1255"); 
 script_bugtraq_id(17138);
 script_osvdb_id(23950);

 script_name(english:"MERCUR Messaging IMAP Service Multiple Command Remote Overflow");
 script_summary(english:"Checks for buffer overflows in Mercur Mailserver/Messaging IMAP Services");

 script_set_attribute(attribute:"synopsis", value:
"The remote IMAP server is affected by a remote buffer overflow
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running MERCUR Messaging Server / Mailserver, a
commercial messaging application for Windows. 

The IMAP server component of this software fails to properly copy
overly-long arguments to LOGIN and SELECT commands, which can be
exploited to crash the server and possibly to execute arbitrary code
remotely. 

Note that the services run by default with LOCAL SYSTEM privileges,
which means that an unauthenticated attacker can potentially gain
complete control of the affected host." );
 script_set_attribute(attribute:"see_also", value:"http://lists.grok.org.uk/pipermail/full-disclosure/2006-March/043972.html" );
 script_set_attribute(attribute:"solution", value:
"No patch information at this time. 
 
Filter access to the IMAP4 Service, so that it can be used by trusted
sources only." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mercur Messaging 2005 IMAP Login Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/03/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/03/16");
 script_cvs_date("$Date: 2015/05/22 14:14:42 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 script_category(ACT_DENIAL);
 script_family(english:"Gain a shell remotely");
 script_copyright(english:"This script is Copyright (C) 2006-2015 Ferdy Riphagen");
 script_dependencies("find_service1.nasl");
 script_require_ports("Services/imap", 143);
 exit(0);
}

include("imap_func.inc");
include("global_settings.inc");

port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port)) exit(0);

banner = get_imap_banner(port:port);
#debug_print("The remote IMAP banner is: ", banner, "\r\n");
if (banner && "MERCUR IMAP4" >< banner) {
  soc = open_sock_tcp(port);
  if (!soc) exit(0);

  exp = string("a0 LOGIN ", crap(data:raw_string(0x41), length:300), "\r\n");
  send(socket:soc, data:exp);

  recv = recv(socket:soc, length:1024);
  #debug_print("Response: ", recv, "\r\n");
  close(soc);

  soc = open_sock_tcp(port);
  if (soc) {
   send(socket:soc, data:string("a1 CAPABILITY \r\n"));
   recv2 = recv(socket:soc, length:1024);
   #debug_print("Response2: ", recv2, "\r\n");
   close(soc);
  }

  if (!soc || (!strlen(recv2))) { 
   security_hole(port);
  }
}
