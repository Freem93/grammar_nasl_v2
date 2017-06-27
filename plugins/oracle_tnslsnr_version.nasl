#
# oracle_tnslsnr_version - NASL script to do a TNS VERSION command against the
# Oracle tnslsnr
#
# James W. Abendschan <jwa@jammed.com>
#
# modified by Axel Nennker 20020306
# modified by Sullo 20041206
# modified by Tenable
#   - moved check for BID 1853 to a separate plugin.
#

# Changes by Tenable:
# - Revised plugin title (6/12/09)

include("compat.inc");

if (description)
{
	script_id(10658);
 	script_version ("$Revision: 1.45 $");
 	script_cvs_date("$Date: 2014/07/11 19:10:05 $");

	script_name(english: "Oracle Database tnslsnr Service Remote Version Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"An Oracle tnslsnr service is listening on the remote port." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the Oracle tnslsnr service, a network
interface to Oracle databases.  This product allows a remote user to
determine the presence and version number of a given Oracle
installation." );
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port so that only authorized hosts can
connect to it." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/05/01");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:listener");
 script_end_attributes();

	script_summary(english: "connects and issues a TNS VERSION command");
	script_category(ACT_GATHER_INFO);
	script_family(english: "Databases");
	script_copyright(english: "(C) 2001-2014 James W. Abendschan <jwa@jammed.com> (GPL)");
	script_dependencie("find_service1.nasl");
	script_require_ports("Services/unknown", 1521, 1527);
	exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

function tnscmd(sock, command)
{
	local_var clen_h, clen_l, command_length, packet, packet_length, plen_h, plen_l;

	# construct packet
	
	command_length = strlen(command);
	packet_length = command_length + 58;

	# packet length - bytes 1 and 2

	plen_h = packet_length / 256;
	plen_l = 256 * plen_h;			# bah, no ( ) ?
	plen_l = packet_length - plen_h;

	clen_h = command_length / 256;
	clen_l = 256 * clen_h;
	clen_l = command_length - clen_l;


	packet = raw_string(
		plen_h, plen_l, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 
		0x01, 0x36, 0x01, 0x2c, 0x00, 0x00, 0x08, 0x00, 
		0x7f, 0xff, 0x7f, 0x08, 0x00, 0x00, 0x00, 0x01, 
		clen_h, clen_l, 0x00, 0x3a, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x34, 0xe6, 0x00, 0x00, 
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, command
		);


	send (socket:sock, data:packet);
}

# Reply comes in 2 packets.  The first is the reply to the connection
# request, and if that is successful, the second contains the reply to
# the version request.
#
# The TNS packets come with a 8 byte header and the header contains
# the packet length.  The first 2 bytes of the header are the total
# length of the packet in network byte order.  
#
# Steven Procter, Nov 11 2002

function unpack_short(buf, offset) {
	local_var result;

	if ( offset + 1 >= strlen(buf) )
		return NULL;
	result = ord(buf[offset]) * 256 + ord(buf[offset + 1]);
	return result;
}

function extract_version(socket, port) {
	local_var flags, header, remaining, report, rest, tot_len, version;

	header = recv(socket:socket, length:8, timeout:5);
	if ( strlen(header) < 5 ) return 0;
	if (ord(header[4]) == 4) {
		report = 
"A TNS service is running on this port but it
refused to honor an attempt to connect to it.
(The TNS reply code was " + ord(header[4]) + ")";
		security_note(port:port, extra:report);
		return 0;
	}
	if (ord(header[4]) != 2) {
		return 0;
	}
	# read the rest of the accept packet
	tot_len = unpack_short(buf:header, offset:0);
	if ( isnull(tot_len) ) return 0;
	remaining = tot_len - 8;
	rest = recv(socket:socket, length:remaining, timeout:5);
	
	# next packet should be of type data and the data contains the version string
	header = recv(socket:socket, length:8, timeout:5);
	tot_len = unpack_short(buf:header, offset:0);
	if ( isnull(tot_len) ) return 0;
	# check the packet type code, type Data is 6
	if (ord(header[4]) != 6) {
		return 0;
	}

	# first 2 bytes of the data are flags, the rest is the version string.
	remaining = tot_len - 8;
	flags = recv(socket:socket, length:2, timeout:5);
	version = recv(socket:socket, length:remaining - 2, timeout:5);
	return version;
}

function oracle_version(port)
{
	local_var cmd, report, sock, version;

	sock = open_sock_tcp(port);
	if (sock)
	{
		cmd = "(CONNECT_DATA=(COMMAND=VERSION))";
		tnscmd(sock:sock, command:cmd);
		version = extract_version(socket:sock, port:port);
                if (version == 0)
                {
                 return 0;
                }
		register_service(port:port, proto:"oracle_tnslsnr");
		set_kb_item(name:string("oracle_tnslsnr/", port, "/version"),
			    value:version);
		
		report = 
			'\n' +
			'A "version" request returns the following : \n' +
			'\n' +
			version;
		security_note(port:port, extra:report);
		close(sock);
	} 
}

# retrieve and test unknown services

if ( get_port_state(1521) )
	oracle_version(port:1521);
if ( get_port_state(1527) )
	oracle_version(port:1527);


if ( thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  )
{
 port = get_unknown_svc(1521);
 if(!port || port == 1521 || port == 1527  )exit(0);
 if(!get_port_state(port) || ! service_is_unknown(port:port)  )exit(0);
 oracle_version(port:port);
}
