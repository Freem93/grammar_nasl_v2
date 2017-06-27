#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66864);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/02/23 22:37:42 $");

  script_cve_id("CVE-2013-3136");
  script_bugtraq_id(60357);
  script_osvdb_id(94124);
  script_xref(name:"MSFT", value:"MS13-048");

  script_name(english:"MS13-048: Vulnerability in Windows Kernel Could Allow Information Disclosure (2839229)");
  script_summary(english:"Checks version of ntoskrnl.exe");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The Windows kernel on the remote host is affected by an information
disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host contains a flaw in the way the Windows kernel handles
certain page fault system calls.  Successful exploitation could allow
disclosure of kernel memory, which could aid in further attacks."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS13-048");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 8."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS13-048';
kb = '2839229';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'1', win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# Only x86 is affected
arch = get_kb_item_or_exit("SMB/ARCH");
if (arch != "x86") audit(AUDIT_OS_NOT, "a 32-bit Windows version");

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows Server 2012" >< productname || "Windows Server 2008 R2" >< productname || "Small Business Server 2011" >< productname)
  audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8 x86
  hotfix_is_vulnerable(os:"6.2", sp:0,  file:"ntoskrnl.exe", version:"6.2.9200.20708", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", sp:0,  file:"ntoskrnl.exe", version:"6.2.9200.16604", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 7 SP1 x86
  hotfix_is_vulnerable(os:"6.1", sp:1,  file:"ntoskrnl.exe", version:"6.1.7601.22318", min_version:"6.1.7601.21000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1,  file:"ntoskrnl.exe", version:"6.1.7601.18147", min_version:"6.1.7600.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows Vista Service Pack 2 x86 / Windows Server 2008 SP2 x86
  hotfix_is_vulnerable(os:"6.0", sp:2,  file:"ntoskrnl.exe", version:"6.0.6002.23103", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2,  file:"ntoskrnl.exe", version:"6.0.6002.18832", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003 SP2 x86
  hotfix_is_vulnerable(os:"5.2", sp:2,  file:"ntoskrnl.exe", version:"5.2.3790.5157", min_version:"5.2.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows XP SP3 x86
  hotfix_is_vulnerable(os:"5.1", sp:3,  file:"ntoskrnl.exe", version:"5.1.2600.6387", min_version:"5.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb)

)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
