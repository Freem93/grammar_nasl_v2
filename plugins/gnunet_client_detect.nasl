#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(31420);
 script_version ("$Revision: 1.7 $");
 script_cvs_date("$Date: 2011/03/11 21:18:08 $");

 script_name(english: "GNUnet Detection (Client Interface)");

 script_set_attribute(attribute:"synopsis", value:
"This plugin detects GNUnet (client interface)." );
 script_set_attribute(attribute:"description", value:
"The remote target is running GNUNet.
GNUnet is an anonymous peer-to-peer network." );
 script_set_attribute(attribute:"see_also", value:"http://gnunet.org/" );
 script_set_attribute(attribute:"solution", value:
"Make sure the use of this program is in line with
your security policy." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/03/12");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Detect GNUnet client interface");
 script_copyright(english: "This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "find_service2.nasl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Service detection");
 script_require_ports(2087, "Services/unknown");
 exit(0);
}

## include('dump.inc');
include('global_settings.inc');
include('misc_func.inc');

if ( thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") )
{
 port = get_unknown_svc();
 if (! port) port = 2087;
}
else port = 2087;

if (! get_port_state(port)) exit(0);

# GNUnet is "silent", unfortunately.

s = open_sock_tcp(port);
if (! s) exit(0);

# See http://gnunet.org/protocol_cs_afs.php3
send(socket: s, data: '\x00\x04' + # Length
		       '\x00\x0f'); # CS_fs_request_init_index

r = recv(socket: s, length: 8192);
close(s);

## dump(dtitle: 'gnunet', ddata: r);

len = strlen(r);
if (len < 2) exit(0);

len2 = ord(r[0]) * 256 + ord(r[1]);
if (len != len2) exit(0);

if (r == '\x00\x08\x00\x00\x00\x00\x00\x00')
{
 register_service(port: port, proto: 'gnunet-client');
 security_note(port);
 exit(0);
}
