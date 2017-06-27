#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51166);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2015/04/23 21:35:40 $");

  script_cve_id("CVE-2010-3965");
  script_bugtraq_id(42855);
  script_osvdb_id(67784);
  script_xref(name:"MSFT", value:"MS10-094");
  script_xref(name:"IAVA", value:"2010-A-0176");

  script_name(english:"MS10-094: Vulnerability in Windows Media Encoder Could Allow Remote Code Execution (2447961)");
  script_summary(english:"Checks the version of Wmenceng.dll");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Windows
Media Encoder.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of Windows Media Encoder
that incorrectly restricts the path used for loading external
libraries.

If an attacker can trick a user on the affected system into opening a
specially crafted Windows Media Profile (.prx) file located in the
same network directory as a specially crafted dynamic link library
(DLL) file, this issue could be leveraged to execute arbitrary code
subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-094");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
and 2008.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

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

bulletin = 'MS10-094';
kbs = make_list("2447961");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp(xp:4, win2003:3, vista:3) <= 0)
  exit(0, "The host is not affected based on its version / service pack.");

if (hotfix_check_server_core() == 1) exit(0, "Windows Server Core installs are not affected.");

# Locate the Windows Media Encoder install.
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();
port    =  kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

hcf_init = TRUE;

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

progfiles = hotfix_get_programfilesdir();
if (isnull(progfiles))
{
  NetUseDel();
  exit(1, 'Couldn\'t get the Program Files directory.');
}
wme_path = "";

key = "SOFTWARE\Microsoft\Windows Media\Encoder";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"InstallDir");
  if (!isnull(value) && strlen(value[1]))
  {
    wme_path = value[1];
    wme_path = ereg_replace(
      pattern:"%ProgramFiles%",
      replace:progfiles,
      string:wme_path,
      icase:TRUE
    );
  }
  RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);


kb = "2447961";
if (wme_path)
{
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:wme_path);
  if (!is_accessible_share(share:share)) exit(1, "Can't access '"+share+"' share.");

  if (
    hotfix_check_fversion(file:"Wmenceng.dll", path:wme_path, version:"10.0.0.3822", min_version:"10.0.0.0", bulletin:bulletin, kb:kb) == HCF_OLDER ||
    hotfix_check_fversion(file:"Wmenceng.dll", path:wme_path, version:"9.0.0.3374",  min_version:"9.0.0.0", bulletin:bulletin, kb:kb) == HCF_OLDER
  ) vuln = TRUE;
}


# Issue a report if we're vulnerable.
if (vuln)
{
  set_kb_item(name:"SMB/Missing/MS10-094", value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  if (wme_path) exit(0, "The host is not affected.");
  else exit(0, "The host is not affected as the Windows Media Encoder component is not installed.");
}
