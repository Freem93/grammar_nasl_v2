#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92843);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/01/05 21:21:58 $");

  script_cve_id(
    "CVE-2016-3301",
    "CVE-2016-3303",
    "CVE-2016-3304"
  );
  script_bugtraq_id(
    92288,
    92301,
    92302
  );
  script_osvdb_id(
    142745,
    142746,
    142747
  );
  script_xref(name:"MSFT", value:"MS16-097");
  script_xref(name:"IAVA", value:"2016-A-0205");

  script_name(english:"MS16-097: Security Update for Microsoft Graphics Component (3177393)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple vulnerabilities in the Graphics
component due to improper handling of embedded fonts by the Windows
font library. An unauthenticated, remote attacker can exploit these
vulnerabilities, by convincing a user to visit a malicious website or
open a specially crafted document file, to execute arbitrary code in
the context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/security/MS16-097");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/10");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "office_installed.nasl", "microsoft_lync_server_installed.nasl");
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

bulletin = 'MS16-097';

kbs = make_list(
  "3174301",
  "3178034",
  "3176492",
  "3176493",
  "3176495",
  "3115109",
  "3115131",
  "3115481",
  "3115408",
  "3115431",
  "3174302",
  "3174304",
  "3174305"
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

arch = get_kb_item_or_exit('SMB/ARCH', exit_code:1);
os = get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "Windows 8.1" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

systemroot = hotfix_get_systemroot();
if (!systemroot) audit(AUDIT_PATH_NOT_DETERMINED, 'system root');

port = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

if (hotfix_check_fversion_init() == HCF_CONNECT) exit(0, "Unable to create SMB session.");

winsxs = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\WinSxS", string:systemroot);
winsxs_share = hotfix_path2share(path:systemroot);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:winsxs_share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, winsxs_share);
}

files = list_dir(basedir:winsxs, level:0, dir_pat:"microsoft.windows.gdiplus", file_pat:"^gdiplus\.dll$", max_recurse:1);

if (arch == 'x86')
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\ApplicabilityEvaluationCache\Package_for_KB3178034~31bf3856ad364e35~x86~~";
else if (arch == 'x64')
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\ApplicabilityEvaluationCache\Package_for_KB3178034~31bf3856ad364e35~amd64~~";
else key = NULL;

if (!isnull(key))
{
  if (os == '6.1') key = key + '6.0.1.1';
  else if (os == '6.2') key = key + '6.1.1.1';
  else if (os == '6.3') key = key + '6.3.1.0';
  else key = NULL;
}

vuln = 0;

function windows_os_is_vuln()
{
  # hotfix_check_winsxs opens another share
  # we need to save state so our session can be restored
  local_var smb_session = make_array(
    'login',    login,
    'password', pass,
    'domain',   domain,
    'share',    winsxs_share
  );

  local_var kb = "3178034";

  vuln += hotfix_check_winsxs(
    os:'6.0',
    sp:2,
    files:files,
    versions:make_list('5.2.6002.19672', '5.2.6002.23998', '6.0.6002.19672', '6.0.6002.23998'),
    max_versions:make_list('5.2.6002.21000', '5.2.6002.99999', '6.0.6002.21000', '6.0.6002.99999'),
    bulletin:bulletin,
    kb:kb,
    key:key,
    session:smb_session
  );
  vuln += hotfix_check_winsxs(os:'6.1', sp:1, files:files, versions:make_list('6.1.7601.23508'), max_versions:make_list('6.1.7601.99999'), bulletin:bulletin, kb:kb, key:key, session:smb_session);
  vuln += hotfix_check_winsxs(os:'6.2', sp:0, files:files, versions:make_list('6.2.9200.21926'), max_versions:make_list('6.2.9200.99999'), bulletin:bulletin, kb:kb, key:key, session:smb_session);
  vuln += hotfix_check_winsxs(os:'6.3', sp:0, files:files, versions:make_list('6.3.9600.18405'), max_versions:make_list('6.3.9600.99999'), bulletin:bulletin, kb:kb, key:key, session:smb_session);

  if (
    # 10
    hotfix_is_vulnerable(os:"10", sp:0, os_build:"10240", file:"gdiplus.dll", version:"10.0.10240.17071", dir:"\system32", bulletin:bulletin, kb:"3176492") ||
    hotfix_is_vulnerable(os:"10", sp:0, os_build:"10586", file:"gdiplus.dll", version:"10.0.10586.545", min_version:"10.0.10586.0", dir:"\system32", bulletin:bulletin, kb:"3176493") ||
    hotfix_is_vulnerable(os:"10", sp:0, os_build:"14393", file:"gdiplus.dll", version:"10.0.14393.51", min_version:"10.0.14393.0", dir:"\system32", bulletin:bulletin, kb:"3176495")
  ) vuln += 1;
}

function office_is_vuln()
{
  local_var office_versions, office_sp;
  local_var path;

  office_versions = hotfix_check_office_version();
  if (office_versions["14.0"])
  {
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (!isnull(office_sp) && office_sp == 2)
    {
      path = hotfix_append_path(path:hotfix_get_officecommonfilesdir(officever:"14.0"), value:"\Microsoft Shared\Office14");
      if (hotfix_check_fversion(file:"Ogl.dll", version:"14.0.7172.5000", min_version:"14.0.0.0", path:path, bulletin:bulletin, kb:"3115131", product:"Microsoft Office 2010 SP2") == HCF_OLDER)
        vuln++;
    }
  }

  # 2007 SP3
  if (office_versions["12.0"])
  {
    office_sp = get_kb_item("SMB/Office/2007/SP");
    if (office_sp == 3)
    {
      path = hotfix_append_path(path:hotfix_get_officecommonfilesdir(officever:"12.0"), value:"\Microsoft Shared\Office12");
      if (hotfix_check_fversion(file:"Ogl.dll", version:"12.0.6751.5000", min_version:"12.0.0.0", path:path, bulletin:bulletin, kb:'3115109', product:"Microsoft Office 2007 SP3") == HCF_OLDER)
         vuln++;
    }
  }

  # Word Viewer
  if (!empty_or_null(get_kb_list("SMB/Office/WordViewer/*/ProductPath")))
  {
    path = hotfix_append_path(path:hotfix_get_officecommonfilesdir(officever:"11.0"), value:"Microsoft Shared\Office11");
    if (hotfix_check_fversion(file:"gdiplus.dll", version:"11.0.8432.0", min_version:"11.0.0.0", path:path, bulletin:bulletin, kb:'3115481', product:"Microsoft Word Viewer") == HCF_OLDER)
      vuln++;
  }
}

function lync_is_vuln()
{
  local_var lync_count, lync_installs, lync_install;

  lync_count = get_install_count(app_name:"Microsoft Lync");

  # Nothing to do
  if (int(lync_count) <= 0)
    return FALSE;

  lync_installs = get_installs(app_name:"Microsoft Lync");
  foreach lync_install (lync_installs[1])
  {
    #if ("Live Meeting 2007 Console" >< lync_install["Product"])
    #{
    # if (hotfix_check_fversion(file:"pubutil.dll", version:"8.0.6362.252", min_version:"8.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"3174305", product:"Live Meeting 2007 Console") == HCF_OLDER)
    #   vuln++;
    #}
    if (lync_install["version"] =~ "^4\.0\." && "Server" >!< lync_install["Product"])
    {
      # Lync 2010
      if ("Attendee" >!< lync_install["Product"])
      {
        if (hotfix_check_fversion(file:"communicator.exe", version:"4.0.7577.4510", min_version:"4.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"3174301", product:"Microsoft Lync 2010") == HCF_OLDER)
          vuln++;
      }
      # Lync 2010 Attendee
      else if ("Attendee" >< lync_install["Product"])
      {
        if ("user level" >< tolower(lync_install["Product"])) # User
        {
          if (hotfix_check_fversion(file:"MeetingJoinAxAOC.DLL", version:"4.0.7577.4510", min_version:"4.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"3174302", product:lync_install["Product"]) == HCF_OLDER)
            vuln++;
        }
        else # Admin
        {
          if (hotfix_check_fversion(file:"MeetingJoinAxAOC.DLL", version:"4.0.7577.4510", min_version:"4.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"3174304", product:lync_install["Product"]) == HCF_OLDER)
            vuln++;
        }
      }
    }
    # Lync 2013
    else if (lync_install["version"] =~ "^15\.0\." && "Server" >!< lync_install["Product"])
    {
      if (hotfix_check_fversion(file:"Lync.exe", version:"15.0.4849.1000", min_version:"15.0.4700.1000", path:lync_install["path"], bulletin:bulletin, kb:"3115431", product:"Microsoft Lync 2013 (Skype for Business)") == HCF_OLDER)
        vuln++;
    }
    # Skype for Business 2016
    else if (lync_install["version"] =~ "^16\.0\." && "Server" >!< lync_install["Product"])
    {
      # Office 365 Deferred channel
      if (hotfix_check_fversion(file:"Lync.exe", version:"16.0.6001.1087", channel:"Deferred", channel_product:"Lync", path:lync_install["path"], bulletin:bulletin, kb:"3115408", product:"Skype for Business 2016") == HCF_OLDER)
        vuln++;
      # Office 365 Deferred channel 1602
      if (hotfix_check_fversion(file:"Lync.exe", version:"16.0.6741.2063", channel:"Deferred", channel_version:"1602", channel_product:"Lync", path:lync_install["path"], bulletin:bulletin, kb:"3115408", product:"Skype for Business 2016") == HCF_OLDER)
        vuln++;
      # Office 365 First Release for Deferred channel
      if (hotfix_check_fversion(file:"Lync.exe", version:"16.0.6965.2076", channel:"First Release for Deferred", channel_product:"Lync", path:lync_install["path"], bulletin:bulletin, kb:"3115408", product:"Skype for Business 2016") == HCF_OLDER)
        vuln++;
      # Office 365 Current channel
      if (hotfix_check_fversion(file:"Lync.exe", version:"16.0.7070.2036", channel:"Current", channel_product:"Lync", path:lync_install["path"], bulletin:bulletin, kb:"3115408", product:"Skype for Business 2016") == HCF_OLDER)
        vuln++;
      # KB
      if (hotfix_check_fversion(file:"Lync.exe", version:"16.0.4417.1000", channel:"MSI", channel_product:"Lync", path:lync_install["path"], bulletin:bulletin, kb:"3115408", product:"Skype for Business 2016") == HCF_OLDER)
        vuln++;
    }
  }
}

windows_os_is_vuln();
office_is_vuln();
lync_is_vuln();

if (vuln > 0)
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
