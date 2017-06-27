#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55796);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/01/28 22:37:17 $");

  script_cve_id("CVE-2011-1977");
  script_bugtraq_id(48985);
  script_osvdb_id(74403);
  script_xref(name:"MSFT", value:"MS11-066");
  script_xref(name:"IAVB", value:"2011-B-0100");

  script_name(english:"MS11-066: Vulnerability in Microsoft Chart Control Could Allow Information Disclosure (2567943)");
  script_summary(english:"Checks version of System.Web.DataVisualization.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ASP.NET control that could allow
information disclosure.");
  script_set_attribute(attribute:"description", value:
"An information disclosure vulnerability exists in the version of
Microsoft Chart Control installed on the remote Windows host due to
improper handling of special characters in the URI included in an HTTP
GET request.

If a web application hosted on the affected system uses Microsoft
Chart Control, an unauthenticated, remote attacker could leverage this
vulnerability to read the contents of files located in or under the
web site directory. This may result in the disclosure of sensitive
information that could be used in secondary attacks, especially in the
case of the application's web.config.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-066");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for .NET Framework 4.0 and
Chart Control for Microsoft .NET Framework 3.5 Service Pack 1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
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
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");


get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS11-066';
kbs = make_list("2487367", "2500170");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);


get_kb_item_or_exit("SMB/Registry/Enumerated");
windows_version = get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# nb: Server Core is not available for Itanium so this won't keep the
#     plugin from checking Windows 2008 installs on that architecture.
if (
  hotfix_check_server_core() == 1 &&
  windows_version == '6.0'
) exit(0, "Server Core installs for Windows 2008 are not affected.");


# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

hcf_init = TRUE;

# Connect to remote registry.
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

# Find where Chart Controls for .NET Framework 3.5 Service Pack 1 is installed.
cc_path = "";

key = "SOFTWARE\Microsoft\NET Framework Chart Setup\NDP\v3.5";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"InstallPath");
  if (!isnull(item)) cc_path = item[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);


if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");


# Check files.

vuln = 0;

# - .NET Framework 4
if (
  hotfix_is_vulnerable(file:"System.Web.DataVisualization.dll", version:"4.0.30319.461", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319", bulletin:bulletin, kb:'2487367') ||
  hotfix_is_vulnerable(file:"System.Web.DataVisualization.dll", version:"4.0.30319.236", min_version:"4.0.30319.0",   dir:"\Microsoft.NET\Framework\v4.0.30319", bulletin:bulletin, kb:'2487367')
) vuln++;

# - Chart Controls for .NET Framework 3.5 Service Pack 1
if (cc_path)
{
  if (hotfix_is_vulnerable(file:"System.web.datavisualization.design.dll", version:"3.5.30729.5681", path:cc_path, bulletin:bulletin, kb:'2500170')) vuln++;
}


if (vuln)
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
