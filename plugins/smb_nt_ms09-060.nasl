#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42116);
  script_version("$Revision: 1.27 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id("CVE-2009-0901", "CVE-2009-2493", "CVE-2009-2495");
  script_bugtraq_id(35828, 35830, 35832);
  script_osvdb_id(56696, 56698, 56699);
  script_xref(name:"MSFT", value:"MS09-060");
  script_xref(name:"CERT", value:"456745");

  script_name(english:"MS09-060: Vulnerabilities in Microsoft Active Template Library (ATL) ActiveX Controls for Microsoft Office Could Allow Remote Code Execution (973965)");
  script_summary(english:"Checks version of various files");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Office ActiveX controls.");
  script_set_attribute(attribute:"description", value:
"One or more ActiveX controls included in Microsoft Outlook or Visio
and installed on the remote Windows host was compiled with a version
of Microsoft Active Template Library (ATL) that is affected by
potentially several vulnerabilities :

  - An issue in the ATL headers could allow an attacker to
    force VariantClear to be called on a VARIANT that has
    not been correctly initialized and, by supplying a
    corrupt stream, to execute arbitrary code.
    (CVE-2009-0901)

  - Unsafe usage of 'OleLoadFromStream' could allow
    instantiation of arbitrary objects which can bypass
    related security policy, such as kill bits within
    Internet Explorer. (CVE-2009-2493)

  - An attacker who is able to run a malicious component or
    control built using Visual Studio ATL can, by
    manipulating a string with no terminating NULL byte,
    read extra data beyond the end of the string and thus
    disclose information in memory. (CVE-2009-2495)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-060");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Outlook 2002,
2003, and 2007 as well as Visio Viewer 2007.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94, 200, 264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}



include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("audit.inc");

include("misc_func.inc");
get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS09-060';
kbs = make_list("972363", "973709");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "KB 'SMB/Registry/Enumerated' not set to TRUE.");


# Determine the install path for Vision Viewer 2007.
visio_viewer_path = NULL;

port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

hcf_init = TRUE;
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

key = "SOFTWARE\Microsoft\Office";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"InstallRoot");
  if (value) visio_viewer_path = value[1];

  RegCloseKey(handle:key_h);
}
if (isnull(visio_viewer_path))
{
  key = "SOFTWARE\Microsoft\Office\12.0\Common\InstallRoot";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"Path");
    if (value) visio_viewer_path = value[1];

    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);


vuln = 0;

share = '';
lastshare = '';
accessibleshare = FALSE;
#Office
outlook_paths = get_kb_list("SMB/Office/Outlook/*/Path");
if (!isnull(outlook_paths))
{
  foreach install (keys(outlook_paths))
  {
    outlook_path = outlook_paths[install];
    share = hotfix_path2share(path:outlook_path);

    if (share != lastshare || !accessibleshare)
    {
      lastshare = share;
      if (is_accessible_share(share:share))
      {
        accessibleshare = TRUE;
      }
      else accessibleshare = FALSE;
    }
    if (accessibleshare)
    {
      # Outlook 2007
      if ("12.0" >< install)
      {
        if (hotfix_check_fversion(path:outlook_path, file:"Outlmime.dll", version:"12.0.6514.5000", min_version:"12.0.0.0", bulletin:bulletin, kb:'972363') == HCF_OLDER) vuln++;
      }
      # Outlook 2003
      else if ("11.0" >< install)
      {
        if (hotfix_check_fversion(path:outlook_path, file:"Outllib.dll", version:"11.0.8313.0", min_version:"11.0.0.0", bulletin:bulletin, kb:'973705') == HCF_OLDER) vuln++;
      }
      # Outlook 2002
      else if ("10.0" >< install)
      {
        if (hotfix_check_fversion(path:outlook_path, file:"Outllib.dll", version:"10.0.6856.0", min_version:"10.0.0.0", bulletin:bulletin, kb:'973702') == HCF_OLDER) vuln++;
      }
    }
  }
}


# Visio
#
# - Visio Viewer 2007.
if (visio_viewer_path)
{
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:visio_viewer_path);
  if (!is_accessible_share(share:share)) exit(1, "Can't access '"+share+"' share.");

  if (
    hotfix_check_fversion(path:visio_viewer_path, file:"Vpreview.exe", version:"12.0.6513.5000", min_version:"12.0.0.0", bulletin:bulletin, kb:'973709') == HCF_OLDER ||
    hotfix_check_fversion(path:visio_viewer_path, file:"Vviewdwg.dll", version:"12.0.6500.5000", min_version:"12.0.0.0", bulletin:bulletin, kb:'973709') == HCF_OLDER ||
    hotfix_check_fversion(path:visio_viewer_path, file:"vviewer.dll",  version:"12.0.6513.5000", min_version:"12.0.0.0", bulletin:bulletin, kb:'973709') == HCF_OLDER
  ) vuln++;
}
# - nb: we don't check for Visio Viewer 2002 and 2003 because the
#       vulnerabilities are mitigated by applying MS09-034, and we
#       do have a check for that.


if (vuln)
{
  set_kb_item(name:"SMB/Missing/MS09-060", value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
