#
# oracle_tnslsnr_security.nasl - NASL script to do a TNS STATUS 
# command against the Oracle tnslsnr and grep out "SECURITY=OFF"
#
# James W. Abendschan <jwa@jammed.com>
#
# Changes by Tenable:
#   - removed report if password-protected.
#   - Revised plugin title (6/12/09)
#   - Added supplied_logins_only check


include("compat.inc");

if (description)
{
	script_id(10660);
 	script_version ("$Revision: 1.25 $");
 	script_osvdb_id(547);
 	script_cvs_date("$Date: 2015/12/23 21:38:31 $");


	script_name(english:"Oracle Database Listener Program (tnslsnr) Service Blank Password");

 script_set_attribute(attribute:"synopsis", value:
"The remote database service is not password-protected." );
 script_set_attribute(attribute:"description", value:
"The remote Oracle Listener Program (tnslsnr) has no password assigned. 
An attacker may use this fact to shut it down arbitrarily, thus
preventing legitimate users from using it." );
 script_set_attribute(attribute:"solution", value:
"Use the lsnrctrl CHANGE_PASSWORD command to assign a password to the
listener." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/05/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/01/01");
script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:listener");
script_end_attributes();


	script_summary(english: "Determines if the Oracle tnslsnr has been assigned a password.");

	script_category(ACT_GATHER_INFO);
	script_family(english: "Databases");
	script_copyright(english: "(C) 2001-2014 James W. Abendschan <jwa@jammed.com> (GPL)");
	script_dependencie("oracle_tnslsnr_version.nasl");
        script_require_ports("Services/oracle_tnslsnr");
	exit(0);
}

include('global_settings.inc');

if (supplied_logins_only) exit(0, "Nessus is currently configured to not log in with user accounts not specified in the scan policy.");

function tnscmd(sock, command)
{
	local_var clen_h, clen_l, command_length, packet, packet_length, plen_h, plen_l, r;

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
	r = recv(socket:sock, length:8192, timeout:5);

	return (r);
}


function oracle_tnslsnr_security(port)
{
	local_var cmd, reply, sock;

	sock = open_sock_tcp(port);
	if (sock) 
	{
		cmd = "(CONNECT_DATA=(COMMAND=STATUS))";
		reply = tnscmd(sock:sock, command:cmd);
		close(sock);
		if ( ! reply ) return 0;

		if ("SECURITY=OFF" >< reply)
		{
			security_warning(port);
		}
		else if ( "ERROR=(CODE=12618)" >< reply )
		{
		  debug_print("incompatible version of tnslsnr!", level:1);
		} 
	}
}

# tnslsnr runs on different ports . . .

port = get_kb_item("Services/oracle_tnslsnr");
if ( isnull(port)) exit(0);

if(get_port_state(port))
 {
  oracle_tnslsnr_security(port:port);
 }

