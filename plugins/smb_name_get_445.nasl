#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(42410);
 script_version ("$Revision: 1.6 $");

 script_name(english:"Microsoft Windows NTLMSSP Authentication Request Remote Network Name Disclosure");
 script_summary(english:"Using SMB to retrieve information from a Windows host");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the network name of the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host listens on tcp port 445 and replies to SMB requests.

By sending an NTLMSSP authentication request it is possible to obtain
the name of the remote system and the name of its domain." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/06");
 script_cvs_date("$Date: 2011/03/27 01:23:39 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("netbios_name_get.nasl");
 script_require_keys("/tmp/10150/report", "/tmp/10150/port", "/tmp/10150/proto");
 exit(0);
}

#

port = get_kb_item("/tmp/10150/port");
if (isnull(port) || port != "445") exit(0);

proto = get_kb_item("/tmp/10150/proto");
if (isnull(proto) || proto != "tcp") exit(0);

report = get_kb_item("/tmp/10150/report");
if (report) security_note(port: port, proto: proto, extra: report);
