#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59857);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/04 18:02:13 $");

  script_cve_id("CVE-2012-3053");
  script_bugtraq_id(54213);
  script_osvdb_id(83353);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtz72985");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120627-webex");

  script_name(english:"Cisco WebEx ARF Player Buffer Overflow (cisco-sa-20120627-webex)");
  script_summary(english:"Checks WebEx file version numbers");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The video player installed on the remote Windows host has a buffer
overflow vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Cisco WebEx ARF Player installed on the remote host has
a buffer overflow vulnerability.  A remote attacker could exploit this
issue by tricking a user into opening a malicious ARF file, resulting
in arbitrary code execution."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120627-webex
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?94db3b7c");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to the latest version of the WebEx ARF Player as described in
Cisco advisory cisco-sa-20120627-webex."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date",value:"2012/06/27");
  script_set_attribute(attribute:"patch_publication_date",value:"2012/06/27");
  script_set_attribute(attribute:"plugin_publication_date",value:"2012/07/06");
  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:cisco:webex_advanced_recording_format_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("webex_player_installed.nasl");
  script_require_keys("SMB/ARF Player/path");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

path = get_kb_item_or_exit('SMB/ARF Player/path');

share = hotfix_path2share(path:path);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(file:'atjpeg60.dll', version:'2028.1201.300.500', min_version:'2028.0.0.0', path:path) ||  # 28.1.0
  hotfix_is_vulnerable(file:'atas32.dll', version:'2027.1225.311.1300', min_version:'2027.0.0.0', path:path) || # 27.25.11
  hotfix_is_vulnerable(file:'atas32.dll', version:'2.6.32.3', path:path)  # 27.32.2
)
{
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_INST_PATH_NOT_VULN, 'Cisco WebEx ARF Player', path);
}
