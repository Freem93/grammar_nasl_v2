#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89779);

  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/04/14 18:41:29 $");

  script_cve_id("CVE-2016-0133");
  script_bugtraq_id(84035);
  script_osvdb_id(135537);
  script_xref(name:"MSFT", value:"MS16-033");
  script_xref(name:"IAVB", value:"2016-B-0048");

  script_name(english:"MS16-033: Security Update for Windows USB Mass Storage Class Driver to Address Elevation of Privilege (3143142)");
  script_summary(english:"Checks the version of usbstor.sys.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an elevation of privilege
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by a flaw in the Windows USB Mass Storage Class
driver due to improper validation of objects in memory. A local
attacker can exploit this, via a specially crafted USB device, to
elevate privileges, allowing the execution of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-033");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

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

bulletin = 'MS16-033';
kbs = make_list('3139398', '3140745', '3140768');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
os = get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if ("Windows 8" >< productname && "8.1" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

vuln = 0;

# Need to check WinSxS for Vista / Server 2008 and Windows 10
if (os == "10" || os == "6.1" || os == "6.0")
{
  systemroot = hotfix_get_systemroot();
  if (empty_or_null(systemroot)) audit(AUDIT_PATH_NOT_DETERMINED, 'system root');

  arch = get_kb_item_or_exit('SMB/ARCH');
  build = get_kb_item_or_exit('SMB/WindowsVersionBuild');

  port = kb_smb_transport();
  login  = kb_smb_login();
  pass   = kb_smb_password();
  domain = kb_smb_domain();

  if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

  winsxs = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\WinSxS", string:systemroot);
  winsxs_share = hotfix_path2share(path:systemroot);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:winsxs_share);
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL, winsxs_share);
  }

  files = list_dir(basedir:winsxs, level:0, dir_pat:"_usbstor.inf_", file_pat:"^USBSTOR\.SYS$", max_recurse:1);

  key = NULL;

  # 10 RTM
  if (os == "10" && build == '10240')
  {
    if (arch == "x86")
      key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\ApplicabilityEvaluationCache\Package_for_KB3140745~31bf3856ad364e35~x86~~10.0.1.2";
    else if (arch == "x64")
      key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\ApplicabilityEvaluationCache\Package_for_KB3140745~31bf3856ad364e35~amd64~~10.0.1.2";

    if (
      hotfix_check_winsxs(os:'10',
                          sp:0,
                          files:files,
                          versions:make_list('10.0.10240.16724'),
                          max_versions:make_list('10.0.10586.0'),
                          bulletin:bulletin,
                          kb:'3140745',
                          key:key)
    ) vuln++;
  }

  # 10 threshold 2 (aka 1511)
  if (os == "10" && build == '10586')
  {
    if (arch == "x86")
      key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\ApplicabilityEvaluationCache\Package_for_KB3140768~31bf3856ad364e35~x86~~10.0.1.3";
    else if (arch == "x64")
      key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\ApplicabilityEvaluationCache\Package_for_KB3140768~31bf3856ad364e35~amd64~~10.0.1.3";

    if (
      hotfix_check_winsxs(os:'10',
                          sp:0,
                          files:files,
                          versions:make_list('10.0.10586.162'),
                          max_versions:make_list('10.0.10586.999'),
                          bulletin:bulletin,
                          kb:'3140768',
                          key:key)
    ) vuln++;
  }

  # Windows 7 / Windows Server 2008 R2
  if (os == "6.1")
  {
    if (arch == "x86")
      key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Package_for_KB3139398~31bf3856ad364e35~x86~~6.1.1.1";
    else if (arch == "x64")
      key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Package_for_KB3139398~31bf3856ad364e35~amd64~~6.1.1.1";

    if (
      hotfix_check_winsxs(os:'6.1',
                          sp:1,
                          files:files,
                          versions:make_list('6.1.7601.19144', '6.1.7601.23344'),
                          max_versions:make_list('6.1.7601.20000', '6.1.7601.99999'),
                          bulletin:bulletin,
                          kb:'3139398',
                          key:key)
    ) vuln++;
  }

  # Vista / Windows Server 2008
  if (os == "6.0")
  {
    if (arch == "x86")
      key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\ApplicabilityEvaluationCache\Package_for_KB3139398~31bf3856ad364e35~x86~~6.0.1.1";
    else if (arch == "x64")
      key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\ApplicabilityEvaluationCache\Package_for_KB3139398~31bf3856ad364e35~amd64~~6.0.1.1";

    if (
      hotfix_check_winsxs(os:'6.0',
                          sp:2,
                          files:files,
                          versions:make_list('6.0.6002.19595', '6.0.6002.23906'),
                          max_versions:make_list('6.0.6002.20000', '6.0.6002.99999'),
                          bulletin:bulletin,
                          kb:'3139398',
                          key:key)
    ) vuln++;
  }

  NetUseDel();
}

else if (
  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"usbstor.sys", version:"6.3.9600.18224", min_version:"6.3.9600.16000", dir:"\system32\drivers", bulletin:bulletin, kb:"3139398") ||

  # Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"usbstor.sys", version:"6.2.9200.21761", min_version:"6.2.9200.20000", dir:"\system32\drivers", bulletin:bulletin, kb:"3139398") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"usbstor.sys", version:"6.2.9200.17642", min_version:"6.2.9200.16000", dir:"\system32\drivers", bulletin:bulletin, kb:"3139398")
)
  vuln++;


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
