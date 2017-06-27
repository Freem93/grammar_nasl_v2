#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was extracted from Cisco
# Security Notice CVE-2012-4098. The text itself is copyright
# (C) Cisco.
#

include("compat.inc");

if (description)
{
  script_id(70457);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/10/18 00:11:10 $");

  script_cve_id("CVE-2012-4098");
  script_bugtraq_id(62858);
  script_osvdb_id(98129);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtn13055");

  script_name(english:"Cisco NX-OS Software BGP DoS (CSCtn13055)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");

  script_set_attribute(attribute:"description", value:
"A vulnerability in the Border Gateway Protocol (BGP) component of
Cisco NX-OS Software could allow an unauthenticated, remote attacker
to create a denial of service (DoS) condition by causing the BGP
service to reset and resync.

The vulnerability is due to improper filtering of invalid AS Path
values. An attacker could exploit this vulnerability by sending a
malformed BGP update to a downstream peer of the affected device. A
successful exploit could result in the downstream peers resetting the
BGP connection with the affected device.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2012-4098
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e466fe6d");

  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in Cisco bug ID CSCtn13055.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/16");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

device = get_kb_item_or_exit("Host/Cisco/NX-OS/Device");
model = get_kb_item_or_exit("Host/Cisco/NX-OS/Model");
version = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");

# only affects nexus 7000 series systems
if (device != 'Nexus' || model !~ '^7[0-9][0-9][0-9]([^0-9]|$)') audit(AUDIT_HOST_NOT, "affected");

flag = 0;
if (
  cisco_gen_ver_compare(a:version, b:"5.2(0.180)S14") >= 0 &&
  cisco_gen_ver_compare(a:version, b:"5.2(0.218)S0") == -1
) flag++;

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Model             : ' + device + ' ' + model +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.2(0.218)S0' + 
      '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
