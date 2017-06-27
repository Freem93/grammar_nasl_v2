#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99305);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/05/25 21:43:15 $");

  script_cve_id("CVE-2017-0158");
  script_bugtraq_id(97455);
  script_osvdb_id(155339);
  script_xref(name:"MSKB", value:"4015067");

  script_name(english:"KB4015067: Security Update for the Scripting Engine Memory Corruption Vulnerability (April 2017)");
  script_summary(english:"Checks the version of Msado15.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update KB4015067. It is,
therefore, affected by a flaw in the VBScript engine due to improper
handling of objects in memory. An unauthenticated, remote attacker can
exploit this, by convincing a user to visit a malicious website or
open a specially crafted document file, to execute arbitrary code.");
  # https://support.microsoft.com/en-us/help/4015067/security-update-for-the-scripting-engine-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0a7080c2");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0158
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?16f2aac4");
  script_set_attribute(attribute:"solution", value:
"Apply security update KB4015067.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS17-04';
kb = "4015067";
kbs = make_list(kb);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

ado_path = hotfix_get_commonfilesdir() + "\system\ado";
if (!ado_path) audit(AUDIT_PATH_NOT_DETERMINED, 'Common Files');
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:ado_path);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL,share);

if (

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Msado15.dll", version:"6.0.6002.24072", min_version:"6.0.6002.22000", path:ado_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Msado15.dll", version:"6.0.6002.19749", min_version:"6.0.6002.18000", path:ado_path, bulletin:bulletin, kb:kb)

)
{
  replace_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
