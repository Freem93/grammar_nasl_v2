#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(36151);
  script_version("$Revision: 1.32 $");
  script_cvs_date("$Date: 2016/12/09 20:55:00 $");

  script_cve_id("CVE-2009-0086", "CVE-2009-0089", "CVE-2009-0550");
  script_bugtraq_id(34435, 34437, 34439);
  script_osvdb_id(53619, 53620, 53621);
  script_xref(name:"MSFT", value:"MS09-013");
  script_xref(name:"IAVA", value:"2009-A-0034");

  script_name(english:"MS09-013: Vulnerabilities in Windows HTTP Services Could Allow Remote Code Execution (960803)");
  script_summary(english:"Checks version of Winhttp.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an API that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Windows HTTP Services installed on the remote host is
affected by several vulnerabilities :

  - An integer underflow triggered by a specially crafted
    response from a malicious web server (for example,
    during device discovery of UPnP devices on a network)
    may allow for arbitrary code execution. (CVE-2009-0086)

  - Incomplete validation of the distinguished name in a
    digital certificate may, in combination with other
    attacks, allow an attacker to successfully spoof the
    digital certificate of a third-party website.
    (CVE-2009-0089)

  - A flaw in the way that Windows HTTP Services handles
    NTLM credentials may allow an attacker to reflect back
    a user's credentials and thereby gain access as that
    user. (CVE-2009-0550)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-013");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista and 2008.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(20, 189);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS09-013';
kb = "960803";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', vista:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

vuln = 0;

if (
  # Windows Vista and Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Winhttp.dll", version:"6.0.6001.22323", min_version:"6.0.6001.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Winhttp.dll", version:"6.0.6001.18178", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Winhttp.dll", version:"6.0.6000.20971", min_version:"6.0.6000.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Winhttp.dll", version:"6.0.6000.16786", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows XP
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Winhttp.dll", version:"5.1.2600.5727", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"Winhttp.dll", version:"5.1.2600.3494", dir:"\System32", bulletin:bulletin, kb:kb) ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0", file:"Winhttp.dll", version:"5.1.2600.3490", dir:"\System32", bulletin:bulletin, kb:kb)
) vuln++;

hotfix_check_fversion_end();

if (hotfix_check_sp(win2003:3) > 0)
{
  if (hotfix_check_sp(win2003:2) > 0)
    fixed_version = '5.2.3790.3262'; # fix for SP1 (and earlier)
  else
    fixed_version = '5.2.3790.4427'; # fix for SP2

  login   =  kb_smb_login();
  pass    =  kb_smb_password();
  domain  =  kb_smb_domain();
  port    =  kb_smb_transport();

  if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

  r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if ( r != 1 ) audit(AUDIT_SHARE_FAIL, share);

  winsxs = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\WinSxS", string:rootfile);
  files = list_dir(basedir:winsxs, level:0, dir_pat:"microsoft.windows.winhttp", file_pat:"^winhttp\.dll$");

  vuln += hotfix_check_winsxs(os:'5.2', sp:1, files:files, versions:make_list('5.2.3790.3262'), bulletin:bulletin, kb:kb);
  vuln += hotfix_check_winsxs(os:'5.2', sp:2, files:files, versions:make_list('5.2.3790.4427'), bulletin:bulletin, kb:kb);

  NetUseDel();
}


if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  exit(0);
}
else
{
  audit(AUDIT_HOST_NOT, 'affected');
}
