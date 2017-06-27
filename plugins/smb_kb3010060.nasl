#
# (C) Tenable Network Security, Inc.
#

# @DEPRECATED@
#
# Disabled on 2014/11/11.  Deprecated by smb_nt_ms14-064.nasl
#

include("compat.inc");

if (description)
{
  script_id(78627);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/11/12 18:26:10 $");

  script_cve_id("CVE-2014-6352");
  script_bugtraq_id(70690);
  script_osvdb_id(113140);

  script_name(english:"MS KB3010060: Vulnerability in Microsoft OLE Could Allow Remote Code Execution (deprecated)");
  script_summary(english:"Checks if workarounds referenced in KB article have been applied.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing one of the workarounds referenced in
Microsoft Security Advisory 3010060.

The version of Microsoft Office installed on the remote host is
affected by a remote code execution vulnerability due to a flaw in the
OLE package manager. A remote attacker can exploit this vulnerability
by convincing a user to open an Office file containing specially
crafted OLE objects, resulting in execution of arbitrary code in the
context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/3010060");
  script_set_attribute(attribute:"solution", value:
"Apply the Microsoft Fix it solution 'OLE packager Shim Workaround' or
deploy the Enhanced Mitigation Experience Toolkit (EMET) 5.0 and
configure Attack Surface Reduction with the settings provided by
Microsoft.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:W/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS14-060 Microsoft Windows OLE Package Manager Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("microsoft_emet_installed.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

# Deprecated.
exit(0, "This plugin has been deprecated.  Use plugin #79125 (smb_nt_ms14-064.nasl) instead.");

include("audit.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

# Only Office 2007/2010/2013 are affected
office_inst = FALSE;
office_kbs = get_kb_list("SMB/Office/*");
if (!isnull(office_kbs))
{
  office_kbs = make_list(office_kbs);
  foreach item (keys(office_kbs))
  {
    if (item =~ "Office\/(Powerpoint|Word|Excel|Publisher|Access)\/1[245]\.") 
    {
      office_inst = TRUE;
      break;
    }
  }
}
if (!office_inst) audit(AUDIT_NOT_INST,"Affected Office 2007 / 2010 / 2013 Product");

##################################################################################
# Fix it Check
registry_init();

hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
systemroot = hotfix_get_systemroot();
if (!systemroot) audit(AUDIT_FN_FAIL, 'hotfix_get_systemroot');

guid = '{3a9498f9-243d-424b-893a-8da0b0cfad53}';
path = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\" + guid);
RegCloseKey(handle:hklm);

if (isnull(path)) path = systemroot + "\AppPatch\Custom\" + guid + '.sdb';

# Now make sure the file is in place
if (hotfix_file_exists(path:path))
{
  hotfix_check_fversion_end();
  exit(0, "The host is not affected since the Microsoft 'Fix it' has been applied.");
}
hotfix_check_fversion_end();
##################################################################################

##################################################################################
# EMET Check
emet_info = '';
emet_installed = FALSE;
emet_with_dllhost = FALSE;
emet_with_pp = FALSE;
if (!isnull(get_kb_item("SMB/Microsoft/EMET/Installed")))
  emet_installed = TRUE;
emet_list = get_kb_list("SMB/Microsoft/EMET/*");
if (!isnull(emet_list))
{
  foreach entry (keys(emet_list))
  {
    if ("dllhost.exe" >< entry && "/asr" >< entry)
    {
      asr = get_kb_item(entry);
      if (!isnull(asr) && asr == 1)
        emet_with_dllhost = TRUE;
    }
    if (("POWERPNT.EXE" >< entry || "powerpnt.exe" >< entry) && "/asr" >< entry)
    {
      asr = get_kb_item(entry);
      if (!isnull(asr) && asr == 1)
        emet_with_pp = TRUE;
    }
  }
}

if (!emet_installed)
{
  emet_info =
  '\n' + 'Microsoft Enhanced Mitigation Experience Toolkit (EMET) is not' +
  '\n' + 'installed.';
}
# ASR needs to be on both
else if (emet_installed && (!emet_with_dllhost || !emet_with_pp))
{
  emet_info =
  '\n' + 'Microsoft Enhanced Mitigation Experience Toolkit (EMET) is' +
  '\n' + 'installed; however, it is not configured with the recommendations' +
  '\n' + 'from Microsoft to mitigate the vulnerability.';
}

if (emet_with_dllhost && emet_with_pp) exit(0, "The host is not affected as EMET has been configured to mitigate the vulnerability.");
##################################################################################

# If we made it here we don't have any of the fixes.
port = get_kb_item('SMB/transport');
if (!port) port = 445;

if (report_verbosity > 0)
{
  report = '\n' + 'The remote host is missing the OLE packager Shim Workaround.';
  if (emet_info != '') report = report + '\n' + emet_info;
  report += '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
