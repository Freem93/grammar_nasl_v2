#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(12236);
 script_version ("$Revision: 1.14 $");
 script_cvs_date("$Date: 2013/01/25 01:19:09 $");

 script_cve_id("CVE-1999-1061");

 script_name(english:"Lexmark / Dell Printer Unauthenticated Access");

 script_set_attribute(attribute:"synopsis", value:
"The remote printer has no password set." );
 script_set_attribute(attribute:"description", value:
"The remote printer has no password set.  This allows anyone to change
its IP or potentially to intercept print jobs sent to it." );
 script_set_attribute(attribute:"solution", value:
"Telnet to this printer and set a password." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/05/13");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Notifies that the remote printer has no password");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_require_ports(9000);
 exit(0);
}

#
# The script code starts here
#
include('telnet_func.inc');
port = 9000;
if(get_port_state(port))
{
 buf = get_telnet_banner(port:port);
 if ("This session allows you to set the TCPIP parameters for your" >< buf &&
     "Set IP address Options" >< buf  )
     security_hole(port:port, extra: buf);
}
