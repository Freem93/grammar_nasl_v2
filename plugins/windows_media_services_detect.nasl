#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(46016);
  script_version("$Revision: 1.3 $");

  script_name(english:"Windows Media Service Server Detection");
  script_summary(english:"Detects a MMS sound server");

  script_set_attribute(
    attribute:"synopsis",
    value:"A Windows Media Service server is listening on the remote port."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is running a Windows Media Service server, a media
streaming server."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Ensure that use of this software is in agreement with your
organization's acceptable use and security policies."
  );
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value: "2010/04/27");
  script_cvs_date("$Date: 2011/03/11 21:18:10 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");

  script_require_ports(1755);

  exit(0);
}


# Ref: http://download.microsoft.com/download/9/5/E/95EF66AF-9026-4BB0-A41D-A4F81802D92C/%5BMS-MMSP%5D.pdf

include("byte_func.inc");
include("global_settings.inc");
include("smb_func.inc");
include("misc_func.inc");

MMS_USE_PACKET_PAIR = 0xf0f0f0f0;

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);
port = 1755;
if ( ! get_port_state(port) ) exit(0, "Port "+port+" is not open.");
soc = open_sock_tcp(port);
if (!soc) exit(0, "Can't open socket on port "+port+".");

function MMS_TCP()
{
  return mkbyte(0x01) + 	# rep
	 mkbyte(0x00) + 	# version
	 mkbyte(0x00) + 	# version minor
	 mkbyte(0x00) + 	# Padding
	 mkdword(2953575118) +  # Session ID ("0xb00bface")
	 mkdword(strlen(_FCT_ANON_ARGS[0]) + 16) + # Message len
	 'MMS ' + 	# seal
  	 mkdword((strlen(_FCT_ANON_ARGS[0]) + 32)/8) + # Chunklen
	 mkword(0x0000) + # Sequence
	 mkword(0x0000) + # MBZ
  	 crap(length:8, data:'\x00') + # Timestamp
	 _FCT_ANON_ARGS[0];
}	

function MMS_TCP_Recv(socket)
{
 local_var rep, len;

 rep = recv(socket:socket, length:12);
 if ( strlen(rep) != 12 ) return NULL;
 len = getdword(blob:rep, pos:8);
 if ( len > 4096 ) return NULL;
 rep += recv(socket:socket, length:len + 16);
 if ( strlen(rep) < len + 16 ) return NULL;
 return rep;
}

function MMS_TCP_GetChunk()
{
 local_var len;
 if ( isnull(_FCT_ANON_ARGS[0]) ) return NULL;
 len = getdword(blob:_FCT_ANON_ARGS[0], pos:16) * 8 - 32;
 if ( strlen(_FCT_ANON_ARGS[0]) < 32 + len - 1 ) return NULL;
 return substr(_FCT_ANON_ARGS[0], 32, strlen(_FCT_ANON_ARGS[0]) - 1);
}

function MMS_Chunk_MID()
{
 return getdword(pos:4, blob:_FCT_ANON_ARGS[0]);
}
   
	 
function LinkViewerToMacConnect()
{
 local_var subscriberName;
 local_var ret;

 subscriberName = unicode(string:"NSPlayer/7.1.0.1956; ");
 subscriberName += crap(data:'\x00', length:8 - (strlen(subscriberName) % 8));

 ret = mkdword((20 + strlen(subscriberName)) / 8 ) + # Chunklen
        mkdword(0x00030001) +  # MID
        mkdword(MMS_USE_PACKET_PAIR) + # playIncarnation 
        mkdword(0x004000b) +  # MacToViewerProtocolRevision
        mkdword(0x0003001c) + # ViewerTomacProtocolRevision
	subscriberName;
 ret += crap(data:'\x00', length:8 - (strlen(ret) % 8));
 return ret;
}

packet = MMS_TCP(LinkViewerToMacConnect());
send(socket:soc, data:packet);
rep = MMS_TCP_Recv(socket:soc);
if ( isnull(rep) ) exit(1, "The service listening on port "+port+" did not respond.");
chunk = MMS_TCP_GetChunk(rep);
if ( MMS_Chunk_MID(chunk) != 0x00040001 ) exit(1, "The MMS server listening on port "+port+" replied with an invalid MID.");
cbServerVersionInfo = getdword(blob:chunk, pos:48);
if ( cbServerVersionInfo == 0  || ( 64 + (cbServerVersionInfo*2) > strlen(chunk))) exit(1, "The MMS server listening on port "+port+" sent an invalid server length.");
serverVersion = substr(chunk, 64, 64 + (cbServerVersionInfo * 2) - 1);
serverVersion = unicode2ascii(string:serverVersion);

if ( serverVersion !~ "^[0-9.]+$" ) exit(1, "The MMS server listening on port "+port+" sent an invalid server version.");
register_service(port:1755, proto:"ms-streaming");
set_kb_item(name:"ms-streaming/1755/version", value:serverVersion);
security_note(port:1755, extra:'\nVersion ' + serverVersion + ' of Microsoft Media Services is running on this port.');
