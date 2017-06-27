#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20130424-nxosmulti.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(66700);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/12/19 19:30:08 $");

  script_cve_id(
    "CVE-2013-1178",
    "CVE-2013-1179",
    "CVE-2013-1180",
    "CVE-2013-1181"
  );
  script_bugtraq_id(59452, 59454, 59456, 59458);
  script_osvdb_id(92759, 92764, 92768, 92769);
  script_xref(name:"CISCO-BUG-ID", value:"CSCts10593");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtu10630");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtx54822");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtx54830");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130424-nxosmulti");

  script_name(english:"Multiple Vulnerabilities in Cisco NX-OS-Based Products (cisco-sa-20130424-nxosmulti)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"Cisco Nexus, Cisco Unified Computing System (UCS), Cisco MDS 9000
Series Multilayer Switches, and Cisco 1000 Series Connected Grid
Routers (CGR) are all based on the Cisco NX-OS operating system. These
products are affected by one or more of the following
vulnerabilities :

  - Multiple Cisco Discovery Protocol Vulnerabilities in
    Cisco NX-OS-Based Products

  - Cisco NX-OS Software SNMP and License Manager Buffer
    Overflow Vulnerability

  - Cisco NX-OS Software SNMP Buffer Overflow Vulnerability

  - Cisco NX-OS Software Jumbo Packet Denial of Service
    Vulnerability

Cisco has released free software updates that address these
vulnerabilities.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130424-nxosmulti
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2d0830fa");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130424-nxosmulti.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/31");

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

if (
  model !~ "^[134579][0-9][0-9][0-9]([^0-9]|$)" ||
  model =~ "^3548([^0-9]|$)"
) audit(AUDIT_HOST_NOT, "affected");

fixed = '';

# Nexus 1000V 4.0(x), 4.2(1)SV1(4b) and Prior
if (device == 'Nexus' && model =~ '^1000[Vv]$')
{
  if (
    version =~ "^4\.0\(" ||
    version =~ "^4\.2\(1\)SV1\(4[ab]?\)"
  ) fixed = '4.2(1)SV2(1.1)';
}

# Nexus 3000 5.0(3)U1(1x), 5.0(3)U1(2x), 5.0(3)U2(1), 5.0(3)U2(2x), 5.0(3)U3(1)
if (device == 'Nexus' && model =~ '^3[0-9][0-9][0-9]$')
{
  if (
    version =~ "^5\.0\(3\)U1\(1[a-z]?\)" ||
    version =~ "^5\.0\(3\)U1\(2[a-z]?\)" ||
    version =~ "^5\.0\(3\)U2\(1\)" ||
    version =~ "^5\.0\(3\)U2\(2[a-z]?\)" ||
    version =~ "^5\.0\(3\)U3\(1\)"
  ) fixed = '5.0(3)U5(1e)';
}

# Nexus 4000 4.1(2)E1(1g) and Prior
if (device == 'Nexus' && model =~ '^4[0-9][0-9][0-9]$')
{
  if (version =~ "^4\.1(2)E1(1[a-g]?)") fixed = '4.1(2)E1(1j)';
}

# Nexus 5000/5500 4.0(x), 4.1(x), 4.2(x), 5.0(x)
if (device == 'Nexus' && model =~ '^5[0-9][0-9][0-9]$')
{
  if (
    version =~ "^4\.[0-2]\(" ||
    version =~ "^5\.0\("
  ) fixed = '5.2(1)N1(4)';
}

# Nexus 7000 4.1(x), 4.2(x), 5.0(x), 5.1(x), 5.2(4) and Prior, 6.0(x)
if (device == 'Nexus' && model =~ '^7[0-9][0-9][0-9]$')
{
  if (
    version =~ "^4\.[12]\(" ||
    version =~ "^5\.[01]\(" ||
    version =~ "^5\.2\(([0-3][a-z]?|4)\)"
  ) fixed = '5.2(9)';

  if (version =~ "^6\.0\(") fixed = '6.1(1)';
}

# MDS 9000 4.1(x), 4.2(x), 5.0(x), 5.2(4) and Prior
if (device == 'MDS' && model =~ '^9[0-9][0-9][0-9]$')
{
  if (
    version =~ "^4\.[12]\(" ||
    version =~ "^5\.0\(" ||
    version =~ "^5\.2\(([0-3][a-z]?|4)\)"
  ) fixed = '5.2(8)';
}

if (!empty(fixed))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Model             : ' + device + ' ' + model +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
