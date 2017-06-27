#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48288);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/06/30 19:55:38 $");

  script_cve_id("CVE-2010-2561");
  script_bugtraq_id(42300);
  script_osvdb_id(66973);
  script_xref(name:"MSFT", value:"MS10-051");

  script_name(english:"MS10-051: Vulnerability in Microsoft XML Core Services Could Allow Remote Code Execution (2079403)");
  script_summary(english:"Checks version of Msxml3.dll");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through its
Microsoft XML Core Services component.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft XML Core Services (MSXML) 3.0 on the remote
Windows host is affected by a memory corruption vulnerability that can
be triggered when processing certain HTTP responses.

If an attacker can trick a user on the affected system into visiting a
malicious website using Internet Explorer, this issue could be
leveraged to execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-051");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:xml_core_services");
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
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS10-051';
kbs = make_list("2079403");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'2,3', win2003:'2', vista:'1,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

kb = '2079403';
if (
  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:0,             file:"Msxml3.dll", version:"8.110.7600.20728", min_version:"8.110.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0,             file:"Msxml3.dll", version:"8.110.7600.16605", min_version:"8.110.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Msxml3.dll", version:"8.100.5003.0",                                     dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Msxml3.dll", version:"8.100.4002.0",                                     dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Msxml3.dll", version:"8.100.1051.0",                                     dir:"\System32", bulletin:bulletin, kb:kb) ||

  # Windows XP
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Msxml3.dll", version:"8.100.1052.0",                                     dir:"\System32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/MS10-051", value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
