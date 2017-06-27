#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49221);
  script_version("$Revision: 1.28 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id("CVE-2010-2738");
  script_bugtraq_id(43068);
  script_osvdb_id(67984);
  script_xref(name:"MSFT", value:"MS10-063");

  script_name(english:"MS10-063: Vulnerability in Unicode Scripts Processor Could Allow Remote Code Execution (2320113)");
  script_summary(english:"Checks version of Usp10.dll");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to execute arbitrary code on the remote Windows host
using the Unicode Scripts Processor.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Windows or Microsoft Office on the remote
host includes a version of the Unicode Script Processor (Usp10.dll),
also known as Uniscribe, which incorrectly validates a table in
OpenType fonts.

If an attacker can trick a user on the affected system into visiting a
malicious website or opening a specially crafted document with an
application that supports embedded OpenType fonts, such as Microsoft
Office, this issue could be leveraged to execute arbitrary code
subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-063");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
and 2008 as well as Microsoft Office XP, 2003, and 2007.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_nt_ms02-031.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS10-063';
kbs = make_list("2288608", "2288613", "2288621", "981322");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

arch = get_kb_item_or_exit("SMB/ARCH");

rootfile = hotfix_get_systemroot();
if (!rootfile) audit(AUDIT_PATH_NOT_DETERMINED, 'system root');

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

office_versions = hotfix_check_office_version();
office_sps = get_kb_item("SMB/Office/*/SP");
x86_path = hotfix_get_commonfilesdir();
if (!x86_path) audit(AUDIT_PATH_NOT_DETERMINED, 'Common Files');
x86_path += "\Microsoft Shared";

x64_path = hotfix_get_programfilesdirx86();
if (arch == "x64" && !x64_path) audit(AUDIT_PATH_NOT_DETERMINED, 'Program Files (x86)');
if (x64_path) x64_path += "\Common Files\Microsoft Shared";

vuln = 0;

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'1,2') <= 0)
{
  if (
    # Vista / Windows Server 2008
    hotfix_is_vulnerable(os:"6.0", sp:2, arch:"x64", file:"Usp10.dll", version:"1.626.6002.22384", min_version:"1.626.6002.22000", dir:"\SysWOW64", bulletin:bulletin, kb:'981322') ||
    hotfix_is_vulnerable(os:"6.0", sp:2, arch:"x64", file:"Usp10.dll", version:"1.626.6002.18244", min_version:"1.626.6002.18000", dir:"\SysWOW64", bulletin:bulletin, kb:'981322') ||
    hotfix_is_vulnerable(os:"6.0", sp:1, arch:"x64", file:"Usp10.dll", version:"1.626.6001.22672", min_version:"1.626.6001.22000", dir:"\SysWOW64", bulletin:bulletin, kb:'981322') ||
    hotfix_is_vulnerable(os:"6.0", sp:1, arch:"x64", file:"Usp10.dll", version:"1.626.6001.18461",                                 dir:"\SysWOW64", bulletin:bulletin, kb:'981322') ||

    hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Usp10.dll", version:"1.626.6002.22384", min_version:"1.626.6002.22000", dir:"\system32", bulletin:bulletin, kb:'981322') ||
    hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Usp10.dll", version:"1.626.6002.18244", min_version:"1.626.6002.18000", dir:"\system32", bulletin:bulletin, kb:'981322') ||
    hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Usp10.dll", version:"1.626.6001.22672", min_version:"1.626.6001.22000", dir:"\system32", bulletin:bulletin, kb:'981322') ||
    hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Usp10.dll", version:"1.626.6001.18461",                                 dir:"\system32", bulletin:bulletin, kb:'981322') ||

    # Windows 2003 x64 / XP x64
    hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"Usp10.dll", version:"1.422.3790.4695",                                  dir:"\SysWOW64", bulletin:bulletin, kb:'981322') ||
    hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"Usp10.dll", version:"1.422.3790.4695",                                  dir:"\system32", bulletin:bulletin, kb:'981322') ||

    # Windows 2003 x86
    hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x86", file:"Usp10.dll", version:"1.422.3790.4695",                                  dir:"\system32", bulletin:bulletin, kb:'981322') ||

    # Windows XP x86
    hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Usp10.dll", version:"1.420.2600.5969",                                  dir:"\system32", bulletin:bulletin, kb:'981322')
  ) vuln++;
}

if (max_index(keys(office_versions)) > 0)
{
  # Office 2007 SP2
  if (office_versions["12.0"])
  {
    sp = get_kb_item("SMB/Office/2007/SP");
    if (!isnull(sp) && sp == 2)
    {
      paths = get_kb_list('SMB/Office/*/12.0/Path');
      paths = list_uniq(make_list(paths));

      if (!isnull(paths))
      {
        path = paths[0];
        if (hotfix_is_vulnerable(file:"Usp10.dll", version:"1.626.6002.22402", path:path, bulletin:bulletin, kb:'2288621'))
          vuln++;
      }
    }
  }
  # Office 2003 SP3
  if (office_versions["11.0"])
  {
    sp = get_kb_item("SMB/Office/2003/SP");
    if (!isnull(sp) && sp == 3)
    {
      if
      (
        (x86_path && hotfix_is_vulnerable(file:"Usp10.dll", version:"1.626.6000.21258", path:x86_path+"\Office11", bulletin:bulletin, kb:'2288613')) ||
        (x64_path && hotfix_is_vulnerable(file:"Usp10.dll", arch:"x64", version:"1.626.6000.21258", path:x64_path+"\Office11", bulletin:bulletin, kb:'2288613'))
      ) vuln++;
    }
  }

  # Office XP SP3
  if (office_versions["10.0"])
  {
    sp = get_kb_item("SMB/Office/XP/SP");
    if (!isnull(sp) && sp == 3)
    {
      if
      (
        (x86_path && hotfix_is_vulnerable(file:"Usp10.dll", version:"1.420.2600.5969", path:x86_path+"\Office10", bulletin:bulletin, kb:'2288608')) ||
        (x64_path && hotfix_is_vulnerable(file:"Usp10.dll", arch:"x64", version:"1.420.2600.5969", path:x64_path+"\Office10", bulletin:bulletin, kb:'2288608'))
      ) vuln++;
    }
  }
}

# Report whether there's a problem.
if (vuln)
{
  set_kb_item(name:"SMB/Missing/MS10-063", value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
