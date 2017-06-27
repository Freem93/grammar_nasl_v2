#
# NASL script to send a DSIGetStatus / FPGetSrvrInfo to an AppleShare IP
# server & parse the reply
#
# based on http://www.jammed.com/~jwa/hacks/security/asip/asip-status
#
#

include("compat.inc");

if (description)
{
  script_id(10666);
 	script_version ("$Revision: 1.32 $");
  script_cvs_date("$Date: 2017/04/27 14:49:39 $");

	script_name(english: "Apple Filing Protocol Server Detection");
	script_summary(english: "Sends DSIGetStatus request.");

  script_set_attribute(attribute:"synopsis", value:
"An Apple file sharing service is listening on the remote port.");
  script_set_attribute(attribute:"description", value:
"The remote service understands the Apple Filing Protocol (AFP) and
responds to a 'FPGetSrvrInfo' ('DSIGetStatus') request with
information about itself. 

AFP is used to offer file services for Mac OS X as well as the older
Mac OS. In the past, it has also been known as 'AppleTalk Filing
Protocol' and 'AppleShare'.");
  # https://developer.apple.com/library/mac/documentation/Networking/Reference/AFP_Reference/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c5471d64");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Apple_Filing_Protocol");
  script_set_attribute(attribute:"solution", value:"n/a" );
  script_set_attribute(attribute:"risk_factor", value:"None" );

  script_set_attribute(attribute:"plugin_publication_date", value: "2001/05/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

	script_category(ACT_GATHER_INFO);
	script_family(english: "Service detection");

	script_copyright(english: "(C) 2001-2016 James W. Abendschan <jwa@jammed.com> (GPL)");

	script_dependencie("find_service1.nasl");
	script_require_ports(548);
	exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

global_var port;

function b2dw(a, b, c, d)
{
	local_var a1, b1, c1, dword;

	a1 = a * 256 * 256 * 256;
	b1 = b * 256 * 256;
	c1 = c * 256;
	dword = a1 + b1 + c1 + d;
	return(dword);
}

function b2w(low, high)	
{
	local_var word;

	word = high * 256;
	word = word + low;

	return(word);
}

# return a pascal string

function pstring(offset, packet)
{
	local_var plen, i, pstr;

	plen = ord(packet[offset]);
	#display("offset: ", offset, "  length: ", plen, "\n");
	pstr = "";	# avoid interpreter warning
	for (i=1;i<plen+1;i=i+1)
	{
		pstr = pstr + packet[offset+i];
	}
	return (pstr);
}

# pull out counted pstrings in packet starting at offset

function pluck_counted(offset, packet)
{
	local_var count, str, plucked, count_offset, j;
	count = ord(packet[offset]);
	#display("plucking ", count, " items\n");
	str = "";
	plucked = "";
	count_offset = offset + 1;
	for (j=0;j<count;j=j+1)
	{
		str = pstring(offset:count_offset, packet:packet);
		# offset + length of data + length byte
		count_offset = count_offset + strlen(str) + 1;
		plucked = plucked + str;
		# lame coz there's no != ?
		if (j < count-1)
			plucked = plucked + ", ";
	}
	return(plucked);
}


#
# parse FPGetSrvrInfo reply (starting at DSIGetRequest reply packet + 16)
#

function parse_FPGetSrvrInfo(packet)
{
	local_var afpversioncount_offset, machinetype, machinetype_offset, versions, pci_report;
	local_var report, servername, uams, uamcount_offset;
        machinetype_offset = b2w(low:ord(packet[17]), high:ord(packet[16])) + 16;
	machinetype = pstring(offset:machinetype_offset, packet:packet);

        afpversioncount_offset = b2w(low:ord(packet[19]), high:ord(packet[18])) + 16;
	versions = pluck_counted(offset:afpversioncount_offset, packet:packet);

	uamcount_offset = b2w(low:ord(packet[21]), high:ord(packet[20])) + 16;
	uams = pluck_counted(offset:uamcount_offset, packet:packet);

	servername = pstring(offset:26, packet:packet);
	if ( strlen(servername) ) set_kb_item(name:"AFP/hostname", value:servername);

	report = '\n' +
  'Nessus collected the following information about the remote AFP service :\n'+
  '\n'+
  '  Server name  : ' + servername + '\n' +
  '  Machine type : ' + machinetype + '\n' +
  '  UAMs         : ' + uams + '\n' +
  '  AFP versions : ' + versions + '\n';

set_kb_item(name:"Host/OS/AFP/fingerprint", value:versions);

if ("No User Authen" >< uams) {
	report += '\nThe server allows the "guest" user to connect.\n';
	set_kb_item(name:"AFP/GuestAllowed", value:TRUE);
}

if("Cleartxt Passwrd" >< uams)
{
	report += '\nThe server allows cleartext authentication.\n';
  pci_report = 'The remote AppleTalk service accepts cleartext logins.';
  set_kb_item(name:"PCI/ClearTextCreds/" + port, value:pci_report);
}
  security_note(port:port, extra:report);
  register_service(port:port, proto:"appleshare");
}


#
# parse ASIP reply packet
#

function parse_DSIGetStatus(packet)
{
	local_var cmd, flags, reqid, reqidH, reqidL;
	local_var datalen, edo, reserved;

	flags = ord(packet[0]);
	cmd = ord(packet[1]);
	reqidL = ord(packet[2]);
	reqidH = ord(packet[3]);

	reqid = b2w(low:reqidL, high:reqidH);

	if (!(reqid == 57005))
	{
	 exit('Unexpected requid in reply packet', 1);
	}

	# ignore error / data offset DO for now

	edo = b2dw(a:ord(packet[4]), b:ord(packet[5]), c:ord(packet[6]), d:ord(packet[7]));

	datalen = b2dw(a:ord(packet[8]), b:ord(packet[9]), c:ord(packet[10]), d:ord(packet[11]));

	reserved = b2dw(a:ord(packet[12]), b:ord(packet[13]), c:ord(packet[14]), d:ord(packet[15]));

	if (!(cmd == 3))
	{
		exit(1);
	}

	return (parse_FPGetSrvrInfo(packet:packet));
}


#
# send the DSIGetStatus packet
#

function send_DSIGetStatus(sock)
{
	local_var buf, packet;

	packet = raw_string
		(
		0x00,			# 0- request, 1-reply
		0x03,			# 3- DSIGetStatus
		0xad, 0xde, 0x00,	# request ID
		0x00, 0x00, 0x00, 0x00,	# data field
		0x00, 0x00, 0x00, 0x00,	# length of data stream header
		0x00, 0x00, 0x00, 0x00	# reserved
                );

	send (socket:sock, data:packet);
	buf = recv(socket:sock, length:8192, timeout:30);
	if (strlen(buf) == 0)
	{
		exit(1);
	}	
	return(buf);
}


#
# do it
#

function asip_status(port)
{
	local_var packet, s;
	s = open_sock_tcp(port);
	if (s)
	{
		packet = send_DSIGetStatus(sock:s);
		if(strlen(packet) > 17)
		{
		parse_DSIGetStatus(packet:packet);
		} 
		close(s);
	}
}


#
# main
#

port = 548;
if (service_is_unknown(port:port) && get_tcp_port_state(port))
{
	asip_status(port:port);
}
