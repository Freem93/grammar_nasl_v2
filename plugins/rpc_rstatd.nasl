#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10227);
 script_version("$Revision: 1.33 $");
 script_cvs_date("$Date: 2012/09/21 20:08:37 $");

 script_cve_id("CVE-1999-0624");

 script_name(english:"RPC rstatd Service Detection");
 script_summary(english:"Checks the presence of a RPC service");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to leak information about the remote server.");
 script_set_attribute(attribute:"description", value:
"The remote host is running the rstatd RPC service. This service provides
information such as :

 - the CPU usage
 - the system uptime
 - the network usage");
 script_set_attribute(attribute:"solution", value:
"Disable this service if it is not needed.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"1999/08/19");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2012 Tenable Network Security, Inc.");
 script_family(english:"RPC"); 
 script_dependencie("rpc_portmap.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}


#
# The script code starts here
#

include ("misc_func.inc");
include ("sunrpc_func.inc");


days = make_list('Sun','Mon','Tue','Wed','Thu','Fri','Sat');
months = make_list('Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec');

# converts a unix timestamp to a human readable format
function convert_unixtime()
{
  local_var timestamp, clock, ret;
  timestamp = _FCT_ANON_ARGS[0];
  if (isnull(timestamp)) return NULL;

  if ( timestamp < 0 || timestamp >= 2147483647 ) return NULL;

  clock = localtime(timestamp);
  ret = NULL;
  ret = days[clock["wday"]] + " ";
  if ( clock["mday"] < 10 ) ret += "0";
  ret = strcat(ret, months[clock["mon"] - 1], " ", clock["mday"], ", ", clock["year"], " ");
  if ( clock["hour"] < 10 ) ret = strcat(ret, "0");
  ret = strcat(ret, clock["hour"], ":");
  if ( clock["min"] < 10 ) ret = strcat(ret, "0");
  ret = strcat(ret, clock["min"], ":");
  if ( clock["sec"] < 10 ) ret = strcat(ret, "0");
  ret = strcat(ret, clock["sec"]);

  return ret;
}

function uptime (sec)
{
 return string (sec/3600, "h ", (sec/60)%60, "m ", sec%60, "s");
}


RPC_PROG = 100001;
tcp = 0;
port = get_rpc_port2(program:RPC_PROG, protocol:IPPROTO_UDP);
if (!port)
{
 port = get_rpc_port2(program:RPC_PROG, protocol:IPPROTO_TCP);
 tcp = 1;
}


if(port)
{
 if(tcp)
 {
  if (! get_tcp_port_state(port)) exit(0, "TCP port "+port+" is not open.");
  soc = open_sock_tcp (port);
  if (!soc) exit(1, "Failed to open a socket on port "+port+".");
  udp = FALSE;
 }
 else
 {
  if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");
  soc = open_sock_udp (port);
  if (!soc) exit(1, "Failed to open a socket on UDP port "+port+".");
  udp = TRUE;
 }

 data = NULL;

 packet = rpc_packet (prog:RPC_PROG, vers:3, proc:0x01, data:data, udp:udp);

 data = rpc_sendrecv (socket:soc, packet:packet, udp:udp);
 if (isnull(data) || (strlen(data) != 104))
   exit(1, "Unexpected response received on port "+port+".");

 # calc the load avg to two decimal places
 avgload[0] = getdword(blob:data, pos:72);
 avgload[1] = getdword(blob:data, pos:76);
 avgload[2] = getdword(blob:data, pos:80);

 for (i = 0; i < max_index(avgload); i++)
 {
   whole = avgload[i] / 256;
   tens = avgload[i] * 10 / 256 % 10;
   hundreds = avgload[i] * 100 / 256 % 10;
   thousands = avgload[i] * 1000 / 256 % 10;

   if (thousands >= 5) hundreds++;
   if (hundreds == 10)
   {
     hundreds = 0;
     tens++;
   }
   if (tens == 10)
   {
     tens = 0;
     whole++;
   }

   avgload[i] = string(whole, '.', tens, hundreds);
 }

 report = string (
        "\n",
	"uptime: ", uptime(sec:getdword(blob:data, pos:92) - getdword(blob:data, pos:84)),
	"\n",
        "local time: ", convert_unixtime(getdword(blob:data, pos:92)), "\n",
	"cpu usage: ",
	"user ", getdword(blob:data,pos:0), ", ",
	"nice ", getdword(blob:data,pos:4), ", ",
	"system ", getdword(blob:data,pos:8), ", ",
	"idle ", getdword(blob:data,pos:12),
	"\n",
        "load average: ", join(avgload, sep:', '), "\n",
        "interrupts: ", getdword(blob:data, pos:48), "\n",
        "context switches: ", getdword(blob:data, pos:68), "\n",
	"disk transfer: ",
	"d1 ", getdword(blob:data,pos:16), ", ",
	"d2 ", getdword(blob:data,pos:20), ", ",
	"d3 ", getdword(blob:data,pos:24), ", ",
	"d4 ", getdword(blob:data,pos:28),
	"\n",
	"memory: ",
	"pagein ", getdword(blob:data,pos:32), ", ",
	"pageout ", getdword(blob:data,pos:36), ", ",
	"swapin ", getdword(blob:data,pos:40), ", ",
	"swapout ", getdword(blob:data,pos:44),
        "\n",
        "networking: ",
        "rx packets ", getdword(blob:data,pos:52), ", ",
        "rx errors ", getdword(blob:data,pos:56), ", ",
        "tx packets ", getdword(blob:data,pos:100), ", ",
        "tx errors ", getdword(blob:data,pos:60), ", ",
        "collisions ", getdword(blob:data,pos:64),
        "\n"
	);

 if (tcp)
   security_note(port:port, extra:report);
 else
   security_note(port:port, protocol:"udp", extra:report);
}
