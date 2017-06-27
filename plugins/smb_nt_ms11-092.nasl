#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(57278);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id("CVE-2011-3401");
  script_bugtraq_id(50957);
  script_osvdb_id(77660);
  script_xref(name:"IAVA", value:"2011-A-0171");
  script_xref(name:"MSFT", value:"MS11-092");

  script_name(english:"MS11-092: Vulnerability in Windows Media Could Allow Remote Code Execution (2648048)");
  script_summary(english:"Checks the version of Encdec.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The version of Windows Media installed on the remote host has a memory
corruption vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Windows Media Player or Windows Media Center install on the remote
Windows host is affected by the following vulnerability :

  - A memory corruption vulnerability could be triggered
    when parsing a specially crafted DVR-MS (Microsoft
    Digital Video Recording) file. (CVE-2011-3401)

If a remote attacker can trick a user into opening a malicious DVR-MS
file using the affected install, this vulnerability could be leveraged
to execute arbitrary code subject to the user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-092");
  script_set_attribute(
    attribute:"solution",
    value:"Microsoft has released a set of patches for Windows XP, Vista, and 7."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS11-094';
kbs = make_list("2619339", "2619340");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if ("XP" >!< productname && "Windows Vista" >!< productname && "Windows 7" >!< productname)
  exit(0, "The host is running "+productname+" and hence is not affected.");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 7
  hotfix_is_vulnerable(os:"6.1", sp:1,             file:"Encdec.dll", version:"6.6.7601.21840", min_version:"6.6.7601.21000", dir:"\system32", bulletin:bulletin, kb:"2619339") ||
  hotfix_is_vulnerable(os:"6.1", sp:1,             file:"Encdec.dll", version:"6.6.7601.17708", min_version:"6.1.7600.17000", dir:"\system32", bulletin:bulletin, kb:"2619339") ||
  hotfix_is_vulnerable(os:"6.1", sp:0,             file:"Encdec.dll", version:"6.6.7600.21070", min_version:"6.6.7600.20000", dir:"\system32", bulletin:bulletin, kb:"2619339") ||
  hotfix_is_vulnerable(os:"6.1", sp:0,             file:"Encdec.dll", version:"6.6.7600.16899", min_version:"6.6.7600.16000", dir:"\system32", bulletin:bulletin, kb:"2619339") ||

  # Vista
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Encdec.dll", version:"6.6.6002.22726", min_version:"6.6.6002.22000", dir:"\system32", bulletin:bulletin, kb:"2619339") ||
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Encdec.dll", version:"6.6.6002.18528", min_version:"6.6.6002.18000", dir:"\system32", bulletin:bulletin, kb:"2619339") ||

  # Windows XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"Encdec.dll", version:"6.5.3790.4916",                                dir:"\SysWOW64", bulletin:bulletin, kb:"2619339") ||

  # # Windows XP Media Center Edition 2005
  # hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Encdec.dll",  version:"6.5.2715.5512", min_version:"6.5.2700.0",     dir:"\system32", bulletin:bulletin, kb:"2619340") ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Encdec.dll", version:"6.5.2600.6161",                                dir:"\system32", bulletin:bulletin, kb:"2619339")
)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
