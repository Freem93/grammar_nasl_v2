#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66382);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/10/21 20:34:20 $");

  script_name(english:"Android Emulator ADB Port on Remote Host");
  script_summary(english:"Detects the ADB control port of an Android emulator.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host exposes the ADB control port of an Android emulator.");
  script_set_attribute(attribute:"description", value:
"The remote host exposes the ADB (Android Debug Bridge) control port of
an Android emulator allowing full, unauthenticated, root access to the
emulated Android device.");
  script_set_attribute(attribute:"see_also", value:"http://developer.android.com/tools/help/adb.html");
  script_set_attribute(attribute:"solution", value:
"Configure the firewall to prevent access to this port or configure the
emulator software to listen on local interfaces only.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/11");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 5555);

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

# Generic function for generating an ADB server -> Emulator packet.
# Command is a 4-byte string, all capitals.
# adbid and devid are the temporary session IDs that are negotiated
# by each side.
# Similar to the way ARP works, the ADB server sends a packet with
# its source "address" (changes for every new session) with a blank
# device "address", that the device will fill in when it replies.

# data is a string of arbitrary length.
#
# rev is a boolean, and can be NULL. This indicates that we want
# to reverse the session IDs ("addresses") for generating packets
# that we compare against packets we have received from the device.
#
# Assumes that byte order has already been set to little endian.
function gen_adb_pkt(cmd, adbid, devid, data, rev)
{
  local_var arg1, arg2, command_magic, data_checksum, i;

  # The magic field is the 4-byte command xor'd by 0xffffffff.
  command_magic = mkpad(4);
  for (i = 0; i < 4; i++)
    command_magic[i] = mkbyte(ord(cmd[i]) ^ 0xFF);

  # The data checksum is every byte added together (as unsigned ints)
  # converted to a little-endian DWORD.
  data_checksum = 0;
  for (i = 0; i < strlen(data); ++i)
    data_checksum += ord(data[i]);
  data_checksum = mkdword(data_checksum);

  # We reverse the session IDs if rev is specified.
  if (isnull(rev))
  {
    arg1 = adbid;
    arg2 = devid;
  }
  else
  {
    arg1 = devid;
    arg2 = adbid;
  }

  return
    cmd +
    mkdword(arg1) +
    mkdword(arg2) +
    mkdword(strlen(data)) +
    data_checksum +
    command_magic +
    data;
}

# Have a short conversation with the emulated device.
# If the converation goes smoothly, we return TRUE.
# Otherwise, we return FALSE.
function detect_adb_port(port)
{
  local_var adbid, devid, pkt, recv_buf, report, soc, v1, v2;

  # Establish a connection.
  soc = open_sock_tcp(port);
  if (!soc)
    audit(AUDIT_SOCK_FAIL, port, "tcp");

  # Send a CNXN command, and negotiate as host-mode so that we are in
  # control of the emulated device.
  # This is a special case of ADB packet format, where the host picks
  # both arguments. They appear to be version information, rather
  # than used for multiplexing.
  # The values we pick are taken from what ADB v1.0.31 sends.
  v1 = getdword(blob:'\x00\x00\x00\x01', pos:0);
  v2 = getdword(blob:'\x00\x10\x00\x00', pos:0);
  send(socket:soc, data:
    gen_adb_pkt(cmd:"CNXN", adbid:v1, devid:v2, data:'host::\0'));

  # Check if the received packet looks like what we were expecting.
  # The version numbers (arguments 1 and 2) do not flip like they do
  # when new sessions are being created.
  recv_buf = recv(socket:soc, length:55, min:55);
  pkt = gen_adb_pkt(cmd:"CNXN", adbid:v1, devid:v2, data:'device::\0');
  if (recv_buf != pkt)
    return FALSE;

  # Now that we have a connection we are ready to negotiate a session.

  # The Android Debug Bridge seems to generate its half of the
  # session ID at random, so we will do the same.
  adbid = rand();

  # The only session we are going to negotiate is a simple shell
  # command execution.
  pkt = gen_adb_pkt(cmd:"OPEN", adbid:adbid, devid:0, data:'shell:echo nessus\0');
  send(socket:soc, data:pkt);

  # Receive what we expect is an OKAY from the device.
  recv_buf = recv(socket:soc, length:24, min:24);

  # We haven't extracted the device's part of the session ID yet, so
  # can't do an exact match. Instead, we check the length, extract
  # the ID, and then do an exact match.
  if (strlen(recv_buf) != 24)
    return FALSE;

  # Extract the devices's half of the session ID, so we can properly
  # match future packets.
  devid = getdword(blob:recv_buf, pos:4);

  # Now that we have the device's half of the session ID, we can
  # verify that the 24-byte response we received earlier is a real
  # OKAY packet.
  pkt = gen_adb_pkt(cmd:"OKAY", adbid:adbid, devid:devid, rev:TRUE);
  if (recv_buf != pkt)
    return FALSE;

  # Receive the output of the 'echo nessus' command.
  recv_buf = recv(socket:soc, length:32, min:32);

  # Verify that we received what we expected.
  pkt = gen_adb_pkt(cmd:"WRTE", adbid:adbid, devid:devid, data:'nessus\r\n', rev:TRUE);
  if (recv_buf != pkt)
    return FALSE;

  # Acknowledge that we got the output of 'echo nessus'.
  pkt = gen_adb_pkt(cmd:"OKAY", adbid:adbid, devid:devid);
  send(socket:soc, data:pkt);

  # Receive what we expect is going a be a CLSE command from the
  # device.
  recv_buf = recv(socket:soc, length:24, min:24);

  # Verify that we received what we expected.
  pkt = gen_adb_pkt(cmd:"CLSE", adbid:adbid, devid:0, rev:TRUE);
  if (recv_buf != pkt)
    return FALSE;

  # Tell the device that we received their close message, so we're
  # going to close too. Similar to the exchange of TCP FINs.
  pkt = gen_adb_pkt(cmd:"CLSE", adbid:0, devid:devid);
  send(socket:soc, data:pkt);

  # If we've made it this far, we've found an Android device emulator!
  close(soc);

  return TRUE;
}

# Checks if the target host is the loopback interface. IPv6 and IPv4
# compatible.
function isloopbackint()
{
  local_var ip;
  ip = get_host_ip();
  return (ip == "::1" || ip =~ "^127\.");
}

# Check if we're scanning the loopback interface
if (isloopbackint())
  exit (0, "Not scanning the loopback interface.");

# For the ADB server -> Emulator (port 5555, 5557, etc) ports, all
# communications are little-endian.
set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

# Only try all of the unknown services if we're allowed to.
if (thorough_tests && !get_kb_item("global_settings/disable_service_discovery"))
{
  port = get_unknown_svc();
  if (!port) audit(AUDIT_SVC_KNOWN);
}
else
{
  port = 5555;
  if (known_service(port:port))
    exit(0, "The service listening on port " + port + " is already known.");
}

# Check that the port is open before we proceed with detection.
if (!get_tcp_port_state(port))
  audit(AUDIT_PORT_CLOSED, port, "tcp");

# Attempt to detect the service.
if (!detect_adb_port(port:port))
  audit(AUDIT_NOT_DETECT, "An Android emulator ADB control port", port);

# If we did detect the service.
register_service(port:port, ipproto:"tcp", proto:"android_emulator_adb");

security_hole(port);
