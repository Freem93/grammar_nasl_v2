#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76474);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/09/24 23:21:20 $");

  script_osvdb_id(125796);

  script_name(english:"SNMP 'GETBULK' Reflection DDoS");
  script_summary(english:"Sends a 'GETBULK' request with a larger than normal value for max-repetitions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote SNMP daemon is affected by a vulnerability that allows a
reflected distributed denial of service attack.");
  script_set_attribute(attribute:"description", value:
"The remote SNMP daemon is responding with a large amount of data to a
'GETBULK' request with a larger than normal value for
'max-repetitions'. A remote attacker can use this SNMP server to
conduct a reflected distributed denial of service attack on an
arbitrary remote host.");
  # http://www.darkreading.com/attacks-breaches/snmp-ddos-attacks-spike/d/d-id/1269149
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8b551b5c");
  # http://www.prolexic.com/kcresources/prolexic-threat-advisories/prolexic-ddos-threat-advisory-snmp-reflector/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bdb53cfc");
  script_set_attribute(attribute:"solution", value:
"Disable the SNMP service on the remote host if you do not use it.
Otherwise, restrict and monitor access to this service, and consider
changing the default 'public' community string.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"SNMP");
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("snmp_settings.nasl","find_service2.nasl");
  script_require_keys("SNMP/community");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("snmp_func.inc");
include("misc_func.inc");

community = get_kb_item_or_exit("SNMP/community");
timeout = 4;

port = get_kb_item("SNMP/port");
if (!port) port = 161;
if (!get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "UDP");

soc = open_sock_udp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port, "udp");

# Make sure a request for sysDesc works.
oid = "1.3.6.1.2.1.1.1.0";
desc = snmp_request(socket:soc, community:community, oid:oid);
if (isnull(desc)) audit(AUDIT_NOT_LISTEN, "SNMP", port, "UDP");

res = snmp_get_bulk_request(
  socket:soc,
  community:community,
  oid:oid,
  non_repeaters:0,
  max_repetitions:2250
);

# 42 is the size of a standard SNMPv2 request
send_len = 42;
if (typeof(res) == "array")
  recv_len = res[3];
else
  recv_len = strlen(res);

# if we get back at least 5x what we send out
if (!isnull(res) && recv_len > (send_len * 5))
{
  if (report_verbosity >  0)
  {
    report =
      '\n' + 'Nessus was able to determine the SNMP service can be abused in an SNMP' +
      '\n' + 'Reflection DDoS attack :' +
      '\n' +
      '\n' + '  Request size  (bytes) : ' + send_len +
      '\n' + '  Response size (bytes) : ' + recv_len +
      '\n';
    security_warning(port:port, protocol:"udp", extra:report);
  }
  else security_warning(port:port, protocol:"udp");
}
else audit(AUDIT_LISTEN_NOT_VULN, "SNMP", port, "", "UDP");
