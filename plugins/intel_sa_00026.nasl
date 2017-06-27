#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70094);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/06/18 11:44:54 $");

  script_bugtraq_id(44592);
  script_osvdb_id(69156);
  script_xref(name:"IAVB", value:"2010-B-0098");

  script_name(english:"Intel Xeon Baseboard Management Component (BMC) Privilege Escalation (INTEL-SA-00026)");
  script_summary(english:"Check Intel BIOS version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Intel BIOS on the remote device indicates that the
Baseboard Management Component (BMC) firmware it is running is
affected by an unspecified privilege escalation vulnerability.

A knowledgeable remote malicious attacker could leverage this issue to
deny service to legitimate users.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d5284b6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant BIOS and BMC firmware referenced in the
vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

 script_dependencies("bios_get_info_ssh.nasl", "bios_get_info_smb_reg.nasl");
 script_require_keys("BIOS/Version", "BIOS/Vendor");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

vendor = get_kb_item_or_exit("BIOS/Vendor");
if (vendor !~ "^Intel ") audit(AUDIT_HOST_NOT, "affected");

version = get_kb_item_or_exit("BIOS/Version");

# Fixed BMC update packages contain the following BIOS updates:
# * S5500BC/S5520UR
# ** S5500.86B.01.00.0050
# * S5520HC/S5500HCV/S5520SC
# ** S5500.86B.01.00.0050.050620101605
# * S5500WB
# ** S5500.86B.01.00.0054
#
# Last vulnerable updates contain the following BIOS:
# * S5500BC/S5520UR
# ** S5500.86B.01.20.0048.041620101015
# * S5520HC/S5500HCV/S5520SC
# ** S5500.86B.01.20.0048.041620101015
# * S5500WB
# ** S5500.86B.01.20.0048.041620101015
#
# Based on this we can flag devices with BIOS version < 50 as having a vulnerable BMC firmware.

fixed = 'S5500.86B.01.00.0050';

version_parts = split(version, sep:'.', keep:FALSE);
if (max_index(version_parts) < 5)
  exit(0, "Intel BIOS version is not granular enough to make a determination.");

fixed_parts = split(fixed, sep:'.', keep:FALSE);

if (
  version_parts[0] == fixed_parts[0] &&
  version_parts[1] == fixed_parts[1] &&
  version_parts[2] == fixed_parts[2] &&
  # skip checking parts[3] as it contains the minor version
  int(version_parts[4]) < int(fixed_parts[4])
)
{
  if (report_verbosity > 0)
  {
      # Note that the version string contains the minor version in
      # part 3 and the major in part 4, so we swap them for displaying
      short_version = '' + int(version_parts[4]) + '.' + version_parts[3];
      short_fixed = '' + int(fixed_parts[4]) + '.' + fixed_parts[3];
      report =
        '\n' +
        '  Installed version : ' + short_version + ' (' + version + ')\n' +
        '  Fixed version     : ' + short_fixed + ' (' + fixed + ')\n';
      security_warning(port:0, extra:report);
  }
  else security_warning(0);
}
else audit(AUDIT_HOST_NOT, "affected");
