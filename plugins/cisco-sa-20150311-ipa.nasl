#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81972);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/03/24 04:36:33 $");

  script_cve_id("CVE-2015-0654");
  script_bugtraq_id(73042);
  script_osvdb_id(119446);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuq40652");
  script_xref(name:"IAVA", value:"2015-A-0059");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150311-ips");

  script_name(english:"Cisco Intrusion Prevention System MainApp SSL/TLS DoS (cisco-sa-20150311-ips)");
  script_summary(english:"Checks the IPS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote security appliance is missing a vendor-supplied security
patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Intrusion Prevention
System software running on the remote host is affected by a denial of
service vulnerability within the SSL/TLS subsystem due to a race
condition when handling multiple HTTPS requests on the management
interface. A remote attacker, negotiating a number of HTTPS
connections with the management interface, can cause the MainApp
process to become unresponsive, resulting in a denial of service
condition and general system failure.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150311-ips
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?05866d57");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant update referenced in Cisco bug ID CSCuq40652.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:intrusion_prevention_system");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("cisco_ips_version.nasl");
  script_require_keys("Host/Cisco/IPS/Version", "Host/Cisco/IPS/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit('Host/Cisco/IPS/Version');
model   = get_kb_item_or_exit('Host/Cisco/IPS/Model');

fixed_ver = NULL;
cbi = "CSCuq40652";

# Models affected include:
#   - IPS 4345
#   - IPS 4345-DC
#   - IPS 4360
#   - IPS 4510
#   - IPS 4520
#   - IPS 4520-XL
#   - ASA 5512-X IPS SSP
#   - ASA 5515-X IPS SSP
#   - ASA 5525-X IPS SSP
#   - ASA 5545-X IPS SSP
#   - ASA 5555-X IPS SSP
#   - ASA 5585-X IPS SSP-10
#   - ASA 5585-X IPS SSP-20
#   - ASA 5585-X IPS SSP-40
#   - ASA 5585-X IPS SSP-60
ips_pat = "^IPS-4(345(-DC)?|360|510|520(-XL)?)$";
asa_pat = "^ASA55(12|15|25|45|55|85)-SSP(-[1246]0)?$";

if (
  ereg(string:model, pattern:ips_pat) ||
  ereg(string:model, pattern:asa_pat)
)
{
  # Affected versions are 7.2 through the fix
  if (version =~ "^7\.2\([0-9]+(p\d)?\)E4$" || version =~ "^7\.3\([0-2](p\d)?\)E4$")
  {
    fixed_ver = "7.3(3)E4";
  }
}

if (!isnull(fixed_ver))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : ' + cbi       +
      '\n  Model             : ' + model     +
      '\n  Installed release : ' + version   +
      '\n  Fixed release     : ' + fixed_ver +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Cisco IPS', version + ' on model ' + model);
