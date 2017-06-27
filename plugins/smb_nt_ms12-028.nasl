#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58660);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id("CVE-2012-0177");
  script_bugtraq_id(52867);
  script_osvdb_id(81134);
  script_xref(name:"MSFT", value:"MS12-028");
  script_xref(name:"IAVB", value:"2012-B-0041");

  script_name(english:"MS12-028: Vulnerability in Microsoft Office Could Allow Remote Code Execution (2639185)");
  script_summary(english:"Checks version of Works632.cnv.");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host could allow arbitrary code execution.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Works for Windows
document converter that is affected by a heap overflow vulnerability.
If an attacker can trick a user on the affected host into opening a
specially crafted Works file, this issue could be leveraged to run
arbitrary code on the host subject to the user's privileges.");

  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-028");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Office 2007,
Microsoft Works 9, and Microsoft Works 6-9 File Converter.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:works");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:works_6-9_file_converter");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

function works_converter_installed()
{
  local_var domain, found, hklm, item, key, key_h, login, pass;
  local_var port, rc;

  get_kb_item_or_exit("SMB/Registry/Enumerated");

  # Connect to the appropriate share.
  port    =  kb_smb_transport();
  login   =  kb_smb_login();
  pass    =  kb_smb_password();
  domain  =  kb_smb_domain();

  if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

  hcf_init = TRUE;

  # Connect to IPC share.
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL, "IPC");
  }

  # Connect to remote registry.
  hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
  if (isnull(hklm))
  {
    NetUseDel();
    audit(AUDIT_REG_FAIL);
  }

  # Get the location the software was installed at.
  found = FALSE;
  key = "SOFTWARE\Microsoft\Works\Converter\6";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:"Installed");
    if (!isnull(item) && item[1] == 1)
      found = TRUE;

    RegCloseKey(handle:key_h);
  }
  RegCloseKey(handle:hklm);
  NetUseDel(close:FALSE);

  return found;
}

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS12-028";
kbs = make_list("2596871", "2680317", "2680326");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

works_conv_installed = works_converter_installed();

if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");

commonfiles = hotfix_get_officecommonfilesdir(officever:"12.0");
if (!commonfiles) exit(1, "Error getting Office Common Files directory.");

path = commonfiles + "\Microsoft Shared\TextConv";

office_versions = hotfix_check_office_version();
vuln = FALSE;

if (office_versions)
{
  # Office 2007 SP2.
  #
  # Note that the bulletin says Office 2007 SP2 is affected, but the
  # KB says that Microsoft Works Suite 2006 is affected.
  if (office_versions["12.0"])
  {
    office_sp = get_kb_item("SMB/Office/2007/SP");
    if (!isnull(office_sp) && office_sp == 2)
    {
      if (hotfix_check_fversion(file:"Works632.cnv", version:"9.011.0707.0", path:path, bulletin:bulletin, kb:"2596871") == HCF_OLDER) vuln = TRUE;
    }
  }
}

if (!vuln && hotfix_check_works_installed())
{
  if (
    # Works 9.
    hotfix_check_fversion(file:"Works632.cnv", version:"9.011.0707.0", min_version:"9.0.0.0", path:path, bulletin:bulletin, kb:"2680317") == HCF_OLDER
  ) vuln = TRUE;
}

if (!vuln && works_conv_installed)
{
  if (
    # Works 6-9 File Converter.
    hotfix_check_fversion(file:"Works632.cnv", version:"9.11.707.0", min_version:"9.0.0.0", path:path, bulletin:bulletin, kb:"2680326") == HCF_OLDER
  ) vuln = TRUE;
}

if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end();
  exit(0);
}

hotfix_check_fversion_end();
audit(AUDIT_HOST_NOT, 'affected');
