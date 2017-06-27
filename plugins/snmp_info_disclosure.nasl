#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74091);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/24 23:21:20 $");

  script_name(english:"Multiple Vendor SNMP public Community String Information Disclosure");
  script_summary(english:"Checks for an information disclosure.");

  script_set_attribute(attribute:"synopsis", value:
"The remote hosts leaks sensitive information when sending SNMP
requests using the 'public' SNMP community string.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to enumerate sensitive information on the remote
device by sending SNMP requests using 'public' as the SNMP community
string.");
  script_set_attribute(attribute:"solution", value:"Reconfigure or restrict access to the SNMP server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SNMP");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencie("snmp_sysDesc.nasl");
  script_require_keys("SNMP/sysDesc");
  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('snmp_func.inc');
include('obj.inc');

# based off scan_snmp_string() in snmp_func.inc
function scan_snmp_array(socket, community, oid)
{
  local_var soid, tmp, port;

  tmp = make_array();
  soid = oid;

  while(1)
  {
    port = snmp_request_next (socket:socket, community:community, oid:soid);
    if (!isnull(port) && egrep (pattern:string("^", str_replace(string:oid, find:".", replace:'\\.'),"\\."), string:port[0]))
    {
      if (strlen(port[1])) tmp[port[0]] = port[1];
      soid = port[0];
    }
    else break;
  }

  if (max_index(keys(tmp)) <= 0) return NULL;
  else return tmp;
}

function sanitize_str(str)
{
  str = str[0] + crap(data:"*", length:6) + str[strlen(str)-1];
  return str;
}

sys_desc = get_kb_item_or_exit("SNMP/sysDesc");
community = 'public';

port = get_kb_item("SNMP/port");
if (!port) port = 161;
if (!get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "UDP");

soc = open_sock_udp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port, "UDP");

report = '';
affected = FALSE;
users_oid = NULL;
passwords_oid = NULL;
wep_keys_oid = NULL;
wpa_psk_oid = NULL;
ssid_oid = NULL;
check_hash = FALSE;

if ("Ambit Wireless" >< sys_desc && sys_desc =~ "MODEL:[ \t]*U10C019")
{
  affected = TRUE;
  users_oid     = "1.3.6.1.4.1.4684.2.17.1.1.1.1";
  passwords_oid = "1.3.6.1.4.1.4684.2.17.1.1.1.2";
  wep_keys_oid  = "1.3.6.1.4.1.4684.2.14.2.5.1.2";
  wpa_psk_oid   = "1.3.6.1.4.1.4491.2.4.1.1.6.2.2.1.5.6";
  ssid_oid      = "1.3.6.1.4.1.4684.2.14.1.2.0";
}
else if ("Netopia 3347" >< sys_desc)
{
  affected = TRUE;
  wep_keys_oid = "1.3.6.1.4.1.304.1.3.1.26.1.15.1.3";
  ssid_oid     = "1.3.6.1.4.1.304.1.3.1.26.1.9.1.2.1";
  wpa_psk_oid  = "1.3.6.1.4.1.304.1.3.1.26.1.9.1.5.1";
}
else if ("Ubee PacketCable" >< sys_desc)
{
  affected = TRUE;
  users_oid = "1.3.6.1.4.1.4491.2.4.1.1.6.1.1";
  passwords_oid = "1.3.6.1.4.1.4491.2.4.1.1.6.1.2";
  wep_keys_oid = "1.3.6.1.4.1.4684.38.2.2.2.1.5.4.2.3.1.2.12";
  wpa_psk_oid =  "1.3.6.1.4.1.4491.2.4.1.1.6.2.2.1.5.12";
  ssid_oid = "1.3.6.1.4.1.4684.38.2.2.2.1.5.4.1.14.1.3.12";
}
else if (
  "Brocade Communications Systems" >< sys_desc &&
  "ADX 1016-2-PREM" >< sys_desc
)
{
  affected = TRUE;
  check_hash = TRUE;
  users_oid     = "1.3.6.1.4.1.1991.1.1.2.9.2.1.1";
  passwords_oid = "1.3.6.1.4.1.1991.1.1.2.9.2.1.2";
}

if (affected)
{
  if (!isnull(users_oid))
  {
    users = scan_snmp_array(socket:soc, community:community, oid:users_oid);
    if (!isnull(users) && !isnull(passwords_oid))
      passwords = scan_snmp_array(socket:soc, community:community, oid:passwords_oid);

    foreach oid (keys(users))
    {
      report += '\n    Username : ' + users[oid];

      if (!isnull(passwords_oid))
      {
        user_id = oid - users_oid;
        pass_id = passwords_oid + user_id;
        if (!isnull(passwords[pass_id]))
        {
          report += '\n    Password : ' + sanitize_str(str:passwords[pass_id]);
          if (passwords[pass_id] =~ "^\$[0-9]\$" && check_hash) report += " (hash)";
        }
        report += '\n';
      }
    }
  }

  if (!isnull(ssid_oid))
  {
    ssid = snmp_request (socket:soc, community:community, oid:ssid_oid);
    if (ssid) report += '\n    SSID     : ' + ssid + '\n';
  }

  if (!isnull(wpa_psk_oid))
  {
    wpa_psk = snmp_request (socket:soc, community:community, oid:wpa_psk_oid);
    if (ssid) report += '\n    WPA PSK  : ' + sanitize_str(str:wpa_psk) + '\n';
  }

  if (!isnull(wep_keys_oid))
  {
    wep_keys = scan_snmp_array(socket:soc, community:community, oid:wep_keys_oid);
    wep_key_strs = make_list();
    foreach wep_key (keys(wep_keys))
    {
      key = wep_keys[wep_key];
      if (key !~ "^([0-9a-fA-F]{26}|[0-9a-fA-F]{10})$")
        key = hexstr(key);
      if (key =~ "^([0-9a-fA-F]{26}|[0-9a-fA-F]{10})$")
        wep_key_strs = make_list(wep_key_strs, key);
    }

    wep_key_strs = list_uniq(wep_key_strs);
    foreach key (wep_key_strs) report += '\n    WEP Key  : ' + sanitize_str(str:key) + '\n';
  }
}

if (report != '')
{
  report = '\n  SysDesc : ' + sys_desc + '\n' +
           '\n  Leaked information :\n' + 
           report ;
  if (report_verbosity > 0) security_warning(port:port, extra:report, proto:"udp");
  else security_warning(port:port, proto:"udp");
}
else audit(AUDIT_LISTEN_NOT_VULN, "SNMP", port, "server", "UDP");
