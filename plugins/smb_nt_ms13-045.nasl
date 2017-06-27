#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66421);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/01/28 22:37:18 $");

  script_cve_id("CVE-2013-0096");
  script_bugtraq_id(59783);
  script_osvdb_id(93317);
  script_xref(name:"MSFT", value:"MS13-045");

  script_name(english:"MS13-045: Vulnerability in Windows Essentials Could Allow Information Disclosure (2813707)");
  script_summary(english:"Checks version of wlarp.exe");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An application on the remote Windows host has an information disclosure
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Windows Essentials 2011 or 2012 installed on the remote
host has an information disclosure vulnerability.  Windows Writer, part
of Windows Essentials, fails to properly handle specially crafted URLs.
A remote attacker could exploit this by tricking a user into opening a
maliciously crafted URL to override Windows Writer proxy settings and
overwrite files accessible to the user."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-045");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Windows Essentials 2012.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:windows_essentials");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "windows_essentials_installed.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS13-045';
kb = '2813707';

kbs = make_list(kb);
if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

path = get_kb_item_or_exit('SMB/Windows_Essentials/Path');
ver = get_kb_item_or_exit('SMB/Windows_Essentials/Version');

if (ver =~ "^15\.") # Windows Essentials 2011
{
  report =
    '\nWindows Essentials 2011 is installed at the following location :\n\n' +
    path + '\n\n' +
    '\nNo patch is available for Windows Essentials 2011.  Microsoft' +
    '\nrecommends upgrading to Windows Essentials 2012 and applying' +
    '\nKB2813707.\n';
  set_kb_item(name:'SMB/Missing/' + bulletin, value:TRUE);
  hotfix_add_report(report, bulletin:bulletin, kb:kb);
  hotfix_security_warning();
  exit(0);
}
else if (ver !~ "^16\.") # 16.x is Windows Essentials 2012
{
  audit(AUDIT_INST_VER_NOT_VULN, 'Windows Essentials', ver);
}

share = hotfix_path2share(path:path);
if (!is_accessible_share(share:share))
  audit(AUDIT_FN_FAIL, 'is_accessible_share');

if (path[strlen(path) - 1] != "\") # add a trailing backslash if necessary
  path += "\";
path += 'Installer';

if (hotfix_is_vulnerable(file:"Wlarp.exe", version:"16.4.3508.205", min_version:"16.0.0.0", path:path, bulletin:bulletin, kb:kb))
{
  set_kb_item(name:'SMB/Missing/' + bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
