#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84734);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/06 17:11:39 $");

  script_cve_id("CVE-2015-2368", "CVE-2015-2369");
  script_osvdb_id(124593, 124594);
  script_xref(name:"MSFT", value:"MS15-069");
  script_xref(name:"IAVA", value:"2015-A-0167");

  script_name(english:"MS15-069: Vulnerabilities in Windows Could Allow Remote Code Execution (3072631)");
  script_summary(english:"Checks the file version of cewmdm.dll, wcewmdm.dll, mstscax.dll, or atlthunk.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple remote code execution
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by multiple remote code execution
vulnerabilities :

  - A remote code execution vulnerability exists due to
    improper handling of the loading of dynamic link library
    (DLL) files. A remote attacker can exploit this
    vulnerability by placing a specially crafted DLL file in
    a user's current working directory and then convincing
    the user to launch a program designed to load the DLL,
    resulting in the execution of arbitrary code in the
    context of the current user. (CVE-2015-2368)

  - A remote code execution vulnerability exists in
    Microsoft Windows Media Device Manager due to improper
    handling of the loading of dynamic link library (DLL)
    files. A remote attacker can exploit this vulnerability
    by placing a specially crafted DLL file in a user's
    current working directory and then convincing the user
    to open a specially crafted .RTF file, resulting in the
    execution of arbitrary code in the context of the
    current user. (CVE-2015-2369)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-069");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2003, Vista, 2008,
7, 2008 R2, 8.1, and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS15-069';

kbs = make_list('3072631', '3067903', '3070738', '3061512');
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
os = get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2003:'2', vista:'2', win7:'1', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
# Some of the 2k3 checks could flag XP 64, which is unsupported
if ("Windows XP" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

vuln = 0;

#############
#
# KB 3061512
#
#############
kb = '3061512';
if (os == '6.3')
{
  sp = get_kb_item("SMB/CSDVersion");
  if (sp)
  {
    sp = ereg_replace(pattern:".*Service Pack ([0-9]).*", string:sp, replace:"\1");
    sp = int(sp);
  }
  else sp = 0;

  if (sp == 0)
  {
    registry_init();
    hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

    key = "SOFTWARE\Microsoft\Windows\CurrentVersion\SideBySide\Winners\x86_microsoft-windows-atlthunk_31bf3856ad364e35_none_4da81b30e32b69f5\6.3\";
    value = get_registry_value(handle:hklm, item:key);
    if(isnull(value) || (ver_compare(ver:value, fix:'6.3.9600.17898', strict:FALSE) < 0))
    {
      RegCloseKey(handle:hklm);
      close_registry();
      hotfix_add_report('\n  The remote host is missing KB3061512.\n', bulletin:bulletin, kb:kb);
      vuln++;
    }
    else
    {
      RegCloseKey(handle:hklm);
      close_registry();
    }
  }
}

#############
#
# KB 3067903
#
#############
kb = '3067903';
if (
  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"cewmdm.dll", version:"12.0.7601.23075", min_version:"12.0.7601.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"cewmdm.dll", version:"12.0.7601.18872", min_version:"12.0.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"cewmdm.dll", version:"11.0.6002.23710", min_version:"11.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"cewmdm.dll", version:"11.0.6002.19403", min_version:"11.0.6001.0", dir:"\system32", bulletin:bulletin, kb:kb)
) vuln++;


#############
#
# KB 3070738
#
#############
kb = '3070738';
if (
  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mstscax.dll", version:"6.3.9600.17901", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:kb)
) vuln++;

if (vuln)
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
