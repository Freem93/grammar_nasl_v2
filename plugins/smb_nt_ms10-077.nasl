#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49954);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/04/06 22:02:43 $");

  script_cve_id("CVE-2010-3228");
  script_bugtraq_id(43781);
  script_osvdb_id(68556);
  script_xref(name:"MSFT", value:"MS10-077");

  script_name(english:"MS10-077: Vulnerability in .NET Framework Could Allow Remote Code Execution (2160841)");
  script_summary(english:"Checks version of clrjit.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The version of the .NET Framework installed on the remote host allows
arbitrary code execution."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The JIT compiler included with the version of the .NET Framework
installed on the remote host optimizes code based on an incorrect
assessment.

If an attacker can trick a user on the affected host into viewing a
specially crafted web page using a Web browser that can run XAML
Browser Applications (XBAPs), he can leverage this issue to corrupt
memory and in turn execute arbitrary code either in the context of the
currently logged-on user or the service account associated with an
application pool identity.

Note that this issue only affects x64-based versions of Windows."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-077");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for the .NET Framework on
Windows XP, 2003, Vista, 2008, 7, and 2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS10-077';
kbs = make_list("2160841");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2003:'2', vista:'1,2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

arch = get_kb_item_or_exit("SMB/ARCH", exit_code:1);
if (arch != "x64") exit(0, "Only x64-based and Itanium-based systems are affected.");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

dir = "\Microsoft.NET\Framework64\v4.0.30319";

kb = "2160841";
if (
  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1",       file:"clrjit.dll", version:"4.0.30319.336", min_version:"4.0.30319.300", dir:dir, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1",       file:"clrjit.dll", version:"4.0.30319.202",                              dir:dir, bulletin:bulletin, kb:kb) ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0",       file:"clrjit.dll", version:"4.0.30319.336", min_version:"4.0.30319.300", dir:dir, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0",       file:"clrjit.dll", version:"4.0.30319.202",                              dir:dir, bulletin:bulletin, kb:kb) ||

  # Windows 2003 and XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"clrjit.dll", version:"4.0.30319.336", min_version:"4.0.30319.300", dir:dir, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"clrjit.dll", version:"4.0.30319.202",                              dir:dir, bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/MS10-077", value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
