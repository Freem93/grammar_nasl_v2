#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was extracted from Cisco
# Security Notice CVE-2013-1121.  The text itself is copyright (C)
# Cisco.
#

include("compat.inc");

if (description)
{
  script_id(70399);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/10/18 00:11:10 $");

  script_cve_id("CVE-2013-5496");
  script_bugtraq_id(62403);
  script_osvdb_id(97291);
  script_xref(name:"CISCO-BUG-ID", value:"CSCui51551");

  script_name(english:"Cisco Open Network Environment Platform Unvalidated Pointer (CSCui51551)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the Open Network Environment Platform (ONEP) could
allow an authenticated, remote attacker to cause the network element
to reload.

The vulnerability is due to insufficient pointer validation. An
attacker could exploit this vulnerability by sending a crafted packet
to an ONEP-enabled network element. Successful exploitation could
allow the attacker to cause the network element to reload.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2013-5496
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a4341ee5");
  script_set_attribute(attribute:"solution", value:"Apply the patch referenced in Cisco bug ID CSCui51551.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/11");

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

# only affects nexus 3000 series systems
if (device != 'Nexus' || model !~ '^3[0-9][0-9][0-9]([^0-9]|$)') audit(AUDIT_HOST_NOT, "affected");

if (
 version == "6.0(2)U1(1)" ||
 version == "6.0(2)U1(2)"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Model             : ' + device + ' ' + model +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 6.0(2)U1(3)' +
      '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
