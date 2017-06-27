#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10418);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-2000-0109");
 script_bugtraq_id(1080);
 script_osvdb_id(320);

 script_name(english:"Standard & Poor's ComStock MultiCSP Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host appears to be running a client application for a stock
quote server." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be a Standard & Poor's MultiCSP system.

Make sure only authorized systems can connect to it.

In addition, these units ship with several default accounts with a
blank or easily guessed password. However, Nessus has not checked 
for these." );
 script_set_attribute(attribute:"solution", value:
"Protect this host by a firewall" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/05/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/01/31");
 script_cvs_date("$Date: 2011/03/21 01:44:55 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 
 script_summary(english:"Detect if the remote host is a Standard & Poors' MultiCSP");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2011 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_require_ports("Services/telnet", 23);
 script_dependencies("find_service1.nasl");
 exit(0);
}

#
# The script code starts here
#
include("telnet_func.inc");

port = get_kb_item("Services/telnet");
if(!port)port = 23;
if (get_port_state(port))
{
 banner = get_telnet_banner(port: port);
 if(banner)
   {
   if("MCSP - Standard & Poor's ComStock" >< banner)
      security_hole(port:port, extra:'The remote telnet banner is :\n' + banner);
   }
}
