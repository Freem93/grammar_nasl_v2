#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(19376);
 script_version ("$Revision: 1.8 $");
 script_cvs_date("$Date: 2011/03/11 21:18:07 $");
 script_name(english:"CA ARCServe MSSQL Agent Detection");
 script_set_attribute(attribute:"synopsis", value:
"A backup software is listening on this port." );
 script_set_attribute(attribute:"description", value:
"The BrightStor ARCServe MSSQL Agent is installed on the remote
host." );
 script_set_attribute(attribute:"solution", value:
"If this service is not needed, disable it or filter incoming traffic
to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/08/03");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Determine if a remote host is running BrightStor ARCServe MSSQL Agent");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 script_require_ports (6070);
 exit(0);
}

port = 6070;
soc = open_sock_tcp (port);
if (!soc) exit(0);

data = "[LUHISL" + crap(data:"A", length:700);

send (socket:soc, data:data);
ret = recv (socket:soc, length:4096);

if ((strlen(ret) == 8) && ( "0000041b00000000" >< hexstr(ret) ))
{
 security_note (port);
 set_kb_item (name:"ARCSERVE/MSSQLAgent", value:TRUE);
}
