#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74016);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/05/18 04:28:41 $");

  script_cve_id(
    "CVE-2014-2132",
    "CVE-2014-2133",
    "CVE-2014-2134",
    "CVE-2014-2135",
    "CVE-2014-2136"
  );
  script_bugtraq_id(67259, 67260, 67261, 67262, 67264);
  script_osvdb_id(106747, 106748, 106749, 106750, 106751);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuc39458");
  script_xref(name:"IAVB", value:"2014-B-0055");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuh52768");
  script_xref(name:"CISCO-BUG-ID", value:"CSCui72223");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuj07603");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuj87565");
  script_xref(name:"CISCO-BUG-ID", value:"CSCul01163");
  script_xref(name:"CISCO-BUG-ID", value:"CSCul01166");
  script_xref(name:"CISCO-BUG-ID", value:"CSCul87216");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140507-webex");

  script_name(english:"Cisco WebEx WRF Player Multiple Vulnerabilities (cisco-sa-20140507-webex)");
  script_summary(english:"Checks WebEx file version numbers.");

  script_set_attribute(attribute:"synopsis", value:
"The video player installed on the remote Windows host has multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco WebEx WRF Player installed on the remote host has
multiple buffer overflow and memory corruption vulnerabilities. A
remote attacker could exploit these issues by tricking a user into
opening a malicious WRF file, resulting in denial of service or
arbitrary code execution.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140507-webex
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c753937d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of the WebEx WRF Player as described in
Cisco advisory cisco-sa-20140507-webex.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:webex_recording_format_player");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("webex_player_installed.nasl");
  script_require_keys("SMB/WRF Player/path");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

path = get_kb_item_or_exit('SMB/WRF Player/path');

share = hotfix_path2share(path:path);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # T28
  hotfix_is_vulnerable(file:'atdl2006.dll', version:'1028.1208.1100.0500', min_version:'1028.0.0.0', path:path) ||
  # T27LDSP32EP16
  hotfix_is_vulnerable(file:'atdl2006.dll', version:'1027.1232.1016.2300', path:path) ||
  # Orion2.0.0.FCS
  hotfix_is_vulnerable(file:'nbrpse.dll', version:'2029.1332.1200.600', min_version:'2029.1332.0.0', path:path) ||
  # T29L10N
  hotfix_is_vulnerable(file:'nbrpse.dll', version:'2029.1311.900.1100', min_version:'2029.0.0.0', path:path)
)
{
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_INST_PATH_NOT_VULN, 'Cisco WebEx WRF Player', path);
}
