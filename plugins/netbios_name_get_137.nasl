#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(42409);
 script_version ("$Revision: 1.9 $");

 script_osvdb_id(13577);

 script_name(english:"Windows NetBIOS Remote Host Information Disclosure");
 script_summary(english:"Using NetBIOS to retrieve information from a Windows host");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the network name of the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host listens on udp port 137 and replies to NetBIOS nbtscan
requests.  By sending a wildcard request it is possible to obtain the
name of the remote system and the name of its domain." );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/06");
 script_cvs_date("$Date: 2014/06/09 20:25:40 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("netbios_name_get.nasl");
 script_require_keys("/tmp/10150/report", "/tmp/10150/port", "/tmp/10150/proto");
 exit(0);
}

exit(0);
port = get_kb_item("/tmp/10150/port");
if (isnull(port) || port != "137") exit(0);

proto = get_kb_item("/tmp/10150/proto");
if (isnull(proto) || proto != "udp") exit(0);

report = get_kb_item("/tmp/10150/report");
if (report) security_note(port: port, proto: proto, extra: report);
