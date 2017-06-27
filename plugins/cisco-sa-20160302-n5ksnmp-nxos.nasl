#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89783);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/10/18 14:03:57 $");

  script_cve_id("CVE-2015-6260");
  script_osvdb_id(135229);
  script_xref(name:"CISCO-BUG-ID", value:"CSCut84645");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160302-n5ksnmp");

  script_name(english:"Cisco Nexus 5500 / 5600 / 6000 SNMP DoS (cisco-sa-20160302-n5ksnmp)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Nexus device is affected by a denial of service
vulnerability in the Simple Network Management Protocol (SNMP) service
due to improper validation of SNMP Protocol Data Units (PDUs) in SNMP
packets. An unauthenticated, remote attacker can exploit this
vulnerability, via a crafted SNMP packet, to cause the device to
restart, resulting in a denial of service condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160302-n5ksnmp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0267c76");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCut84645.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/09");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

device  = get_kb_item_or_exit("Host/Cisco/NX-OS/Device");
model   = get_kb_item_or_exit("Host/Cisco/NX-OS/Model");

if (device != 'Nexus' || (model !~ '^5[56][0-9][0-9]([^0-9]|$)' && model !~ '^6[0-9][0-9][0-9]([^0-9]|$)'))
  audit(AUDIT_HOST_NOT, "Nexus model 5500 / 5600 / 6000");

version = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");

flag = 0;

if (version == "7.1(1)N1(1)")
  flag++;

if (flag)
{
  report =
  '\n  Model             : ' + device + ' ' + model +
  '\n  Installed version : ' + version +
  '\n  Fixed version     :  7.1(2)N1(1)' +
  '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_HOST_NOT, "affected");
