#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88717);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/04/28 18:15:08 $");

  script_cve_id("CVE-2016-1302");
  script_bugtraq_id(82549);
  script_osvdb_id(133958);
  script_xref(name:"CISCO-BUG-ID", value:"CSCut12998");
  script_xref(name:"IAVA", value:"2016-A-0051");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160203-apic");

  script_name(english:"Cisco Nexus 9000 Series APIC Access Control Vulnerability (CSCut12998)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Nexus 9000 Series device is affected by an access
control vulnerability in the Cisco Application Policy Infrastructure
Controller (APIC) due to a flaw in the eligibility logic of the
role-based access control (RBAC) code. An authenticated, remote
attacker can exploit this, via specially crafted representational
state transfer (REST) requests to the APIC, to make configuration
changes outside of allowed access privileges.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160203-apic
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?73afdd7b");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCut12998");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCut12998.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:nexus_9000");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

device  = get_kb_item_or_exit("Host/Cisco/NX-OS/Device");
model   = get_kb_item_or_exit("Host/Cisco/NX-OS/Model");

# only affects nexus 9000 series systems
if (device != 'Nexus' || model !~ '^9[0-9][0-9][0-9]([^0-9]|$)')
  audit(AUDIT_DEVICE_NOT_VULN, device + ' ' + model);

version = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");

# defensive check for the eregmatches below
if (version !~ "^[0-9.]+\([0-9.]+")
  audit(AUDIT_DEVICE_NOT_VULN, device + ' ' + model, version);

major = eregmatch(pattern:"^([0-9.]+)\(", string:version);
major = major[1];
build = eregmatch(pattern:"^[0-9.]+\(([0-9.]+)", string:version);
build = build[1];

# running software versions prior to 11.0(3h) and 11.1(1j)
if (major == "11.0")
{
  build_fix = "3";
  fix = "11.0(3h)";
}
else if (major == "11.1")
{
  build_fix = "1";
  fix = "11.1(1j)";
}
else
  audit(AUDIT_DEVICE_NOT_VULN, device + ' ' +  model, version);

if (ver_compare(ver:build, fix:build_fix, strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Model             : ' + device + ' ' + model +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(port:0);
  exit(0);
}
else audit(AUDIT_DEVICE_NOT_VULN, device + ' ' + model, version);
