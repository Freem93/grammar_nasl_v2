#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77759);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/05/16 19:35:38 $");

  script_cve_id("CVE-2014-3348");
  script_bugtraq_id(69652);
  script_osvdb_id(111094);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuo69206");
  script_xref(name:"IAVB", value:"2014-B-0127");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140908-ucse");

  script_name(english:"Cisco UCS Integrated Management Controller < 2.3(1) DoS (cisco-sa-20140908-ucse)");
  script_summary(english:"Checks the Cisco Integrated Management Controller version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is running a vulnerable version of Cisco IMC.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote device is running a
version of Cisco Integrated Management Controller (IMC) prior to
2.3(1) running on an E-series blade server. It is, therefore, affected
by a flaw allowing a remote attacker to cause a denial of service by
sending a specially crafted SSH packet to the SSH server running on
the integrated controller. The controller will become unresponsive,
however the operating system running on the blade server itself will
be unaffected.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35588");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2014-3348
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18c0b341");
  # https://tools.cisco.com/bugsearch/bug/CSCuo69206
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84fc727a");

  script_set_attribute(attribute:"solution", value:"Upgrade to firmware version 2.3(1) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:unified_computing_system_integrated_management_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:unified_computing_system");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/19");

  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_imc_detect.nbin");
  script_require_keys("Host/Cisco/CIMC/version", "Host/Cisco/CIMC/model");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


model = get_kb_item_or_exit("Host/Cisco/CIMC/model");
# Version will be in format like 1.0(1) -> 1.0.1
chckver = get_kb_item_or_exit("Host/Cisco/CIMC/version");
version = chckver;
chckver = str_replace(string:chckver, find:"(", replace:".");
chckver = str_replace(string:chckver, find:")", replace:"");

# Vulnerable Models
# Cisco UCS E140D
# Cisco UCS E140DP
# Cisco UCS E160D
# Cisco UCS E160DP
# Cisco UCS E140S M1
# Cisco UCS E140S M2
# Cisco UCS EN120S M2
modptrn = "(UCS EN120S M2|UCS E140S M2|UCS E140S M1|UCS E160DP|UCS E160D|UCS E140DP|UCS E140D)";
model   = eregmatch(string:model, pattern:modptrn);
if (isnull(model)) audit(AUDIT_HOST_NOT, "an affected model");

# There are no releases for this product line that have alpha symbols as of
# 9/18/2014.  The older series product lines do have these symbols. If we
# see one we're either on a future version for this line or on an older
# model like the C series devices.  Either way we know we're not affected.
if (chckver =~ "[A-Za-z]") audit(AUDIT_HOST_NOT, "affected");

# Release    First Fixed  Recommended
#  1.0.1         N/A    Migrate to 2.3.1
#  1.0.2         N/A    Migrate to 2.3.1
#  2.1.0         N/A    Migrate to 2.3.1
#  2.2.0         N/A    Migrate to 2.3.1
#  2.3.1        2.3.1         2.3.1
if (
  ver_compare(ver:chckver, fix:"1.0.1", strict:FALSE) >= 0 &&
  ver_compare(ver:chckver, fix:"2.2.0", strict:FALSE) <= 0
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Model             : ' + model[1] +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.3(1)' +
      '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
}
else audit(AUDIT_HOST_NOT, "affected");
