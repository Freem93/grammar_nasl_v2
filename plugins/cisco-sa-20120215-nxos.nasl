#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20120215-nxos.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(66698);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/12/19 19:30:08 $");

  script_bugtraq_id(52027);
  script_xref(name:"CISCO-BUG-ID", value:"CSCti23447");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120215-nxos");

  script_name(english:"Cisco NX-OS Malformed IP Packet DoS (cisco-sa-20120215-nxos)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"Cisco NX-OS Software is affected by a denial of service (DoS)
vulnerability that causes Cisco Nexus 1000v, 1010, 5000, and 7000
Series Switches, and the Cisco Virtual Security Gateway (VSG) for
Nexus 1000V Series Switches, that are running affected versions of
Cisco NX-OS Software to reload when the IP stack processes a malformed
IP packet. Cisco has released free software updates that address this
vulnerability.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120215-nxos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?deffebbc");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20120215-nxos.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

fixed = '';

device = get_kb_item_or_exit("Host/Cisco/NX-OS/Device");
model = get_kb_item_or_exit("Host/Cisco/NX-OS/Model");
version = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");

# only affects Nexus devices
if (device != 'Nexus' || model !~ "^[156][0-9][0-9][0-9]([^0-9]|$)") audit(AUDIT_HOST_NOT, "affected");

# 1000V 4.x affected, save for releases after 4.2(1)VSG1(3.1), 4.2(1)SV1(4b), and 4.2(1)SV1(5.1)
if (model =~ '^1000[Vv]$')
{
  if (
    version =~ "^4\.0\(" ||
    version =~ "^4\.2\(1\)SV1\(([0-3][a-z]?|4a?)\)"
  ) fixed = '4.2(1)SV1(4b) / 4.2(1)SV1(5.1)';

  if (version =~ "^4\.2\(1\)VSG1\([12]\)") fixed = '4.2(1)VSG1(3.1)';
}

# 1010 4.x prior to 4.2(1)SP1(4)
if (model =~ '^101[0-9]([^0-9]|$)')
{
  if (
    version =~ "^4\.0\(" ||
    version =~ "^4\.2\(1\)SP1\([0-3][a-z]?\)"
  ) fixed = '4.2(1)SP1(4)';
}

# 5000 4.x affected, 5.0(2)N1(1) is the first 5.x release
if (model =~ '^5[0-9][0-9][0-9]([^0-9]|$)')
{
  if (version =~ "^4\.") fixed = '5.0(2)N1(1)';
}

# 7000 4.2.x < 4.2(8), 5.0.x < 5.0(5), 5.1(1) is first 5.1.x release
if (model =~ '^7[0-9][0-9][0-9]([^0-9]|$)')
{
  if (version =~ "^4\.2\([0-7][a-z]?\)") fixed = '4.2(8)';
  if (version =~ "^5\.0\([0-4][a-z]?\)") fixed = '5.0(5) / 5.1(1)';
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
