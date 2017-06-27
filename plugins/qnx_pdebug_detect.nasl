#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48353);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/23 20:42:24 $");

  script_name(english:"QNX pdebug Service Detection");
  script_summary(english:"Connect to QNX pdebug");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary commands can be run on this port." );
  script_set_attribute(attribute:"description", value:
"The QNX pdebug remote debugging service is running on this host. 
pdebug should only be used only in development phase.

Through this service, it is possible to upload and execute arbitrary
code on the host, read or modify memory, stop running processes, etc. 

An attacker can use this service to take complete control of the
affected device." );
  script_set_attribute(attribute:"solution", value: 

"Filter incoming traffic to this port or disable the debug agent.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?6ec74396");
  script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?4a817c2a");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/17");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
  script_family(english:"Service detection");
  script_require_ports("Services/unknown");
  script_dependencies("find_service2.nasl");
  exit (0);
}

include("global_settings.inc");
include("misc_func.inc");
include("network_func.inc");

global_var	port;

function checksum(data)
{
  local_var	sum, i, n;
  n = strlen(data);
  sum = 0;
  for (i = 0; i < n; i ++)
  {
    sum = sum + ord(data[i]);
  }
  sum = (sum >>> 8) + (sum & 0xff);
  sum += (sum >>> 8);
  sum = (~sum) & 0xFF;
  return raw_string(sum);
}

function check(r, len)
{
  local_var	l, sum, z;

  l = strlen(r);
  while (l > 3)
  {
    z =  substr(r, 0, 3);
    if (z == '\x7E\x01\xFE\x7E' || z == '\x7E\x00\xFF\x7E')
    {
      r = substr(r, 4);
      l -= 4;
    }
    else
      break;
  }

  if (! isnull(len))
  {
    if (l < len) return "Short packet";
    if (l > len) return "Packet is too long";
  }

  if (r[0] != '\x7E' || r[l-1] != '\x7E') return "Invalid start/end marker";
  if (r[1] != '\x22') return "Not OK status ("+ord(r[1])+")";
  sum = checksum(data: substr(r, 1, len - 2));
  if (sum != '\0') return "Invalid checksum";
  return "";
}

function recvcheck(s, len)
{
  local_var	r, z;

  r = recv(socket: s, length: 128, min: len);
  z = check(r: r, len: len);
  if (z)
  {
    close(s);
    exit(0, z + " on port "+port+".");
  }
}

# pdebug is unfortunately the kind of TCP service that just drop 
# invalid data without answering

port = get_unknown_svc();
if (! port) exit(0, "No unknown service is running.");

# pdebug _sometimes_ returns a banner.
b = get_unknown_banner(port: port, dontfetch: 1);
if (strlen(b) > 0)
{
  if (b != '\x7E\x00\xFF\x7E')
    exit(0, "The service on port "+port+" is not pdebug.");
}
else if (get_kb_item("global_settings/disable_service_discovery"))
  exit(1, "Service discovery is disabled and the service runs on an arbitrary port.");
else if (! thorough_tests)
  exit(1, "This plugin is slow and the 'Perform thorough tests' setting is not set.");

s = open_sock_tcp(port);
if (! s) exit(1, "Can't open a socket on TCP port "+port+".");

# See http://sourceware.org/ml/gdb-patches/2003-09/txt00001.txt
# Messages start and end with \x7E

send(socket: s, data: 
	'\x7E' +
	'\x00' +	# Reset channel
	'\xFF' +	# Checksum
	'\x7E' );

# Connect
send(socket: s, data: 
	'\x7E' +
	'\x00' +	# Command: connect
	'\x00' +	# Subcommand
	'\x00' +	# MID
	'\x01' +	# Channel: 1 = debug
	'\x00' +	# Major
	'\x03' +	# Minor
	'\x00\x00' +	# Spare
	'\xFB' +	# Checksum
	'\x7E' );

r = recvcheck(s: s, len: 11);

# protover
send(socket: s, data:
	'\x7E' +
	'\x17' +	# Command: CPU INFO
	'\x00' +	# Subcommand
	'\x03' +	# MID
	'\x01' +	# Channel: 1 = debug
	'\x00' +	# Major
	'\x03' +	# Minor
	'\xe1' +	# Checksum
	'\x7e' );

r = recvcheck(s: s, len: 11);

close(s);

register_service(port: port, proto: "qnx-pdebug");
security_hole(port: port);
