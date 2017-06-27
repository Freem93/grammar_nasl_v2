#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99308);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/05/25 21:43:15 $");

  script_cve_id("CVE-2017-0192");
  script_bugtraq_id(97452);
  script_osvdb_id(155356);
  script_xref(name:"MSKB", value:"4015380");

  script_name(english:"KB4015380: Security Update for the ATMFD.dll Information Disclosure Vulnerability (April 2017)");
  script_summary(english:"Checks the version of atmfd.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update KB4015380. It is,
therefore, affected by an information disclosure vulnerability in the
Adobe Type Manager Font Driver (ATMFD.dll) due to improper handling of
objects in memory. An unauthenticated, remote attacker can exploit
this, by convincing a user to open a specially crafted document or
visit a malicious web page, to disclose sensitive information.");
  # https://support.microsoft.com/en-us/help/4015380/security-update-for-atmfd-dll-information-disclosure-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6fadc4a4");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0192
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1396dba0");
  script_set_attribute(attribute:"solution", value:
"Apply security update KB4015380.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");

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
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS17-04';
kbs = make_list("4015380");

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if ( hotfix_is_vulnerable(os:"6.0", sp:2, file:"atmfd.dll", version:"5.1.2.251", dir:"\system32", bulletin:bulletin, kb:'4015380') )
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
