#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(57949);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/11/20 22:07:59 $");

  script_cve_id(
    "CVE-2012-0019",
    "CVE-2012-0020",
    "CVE-2012-0136",
    "CVE-2012-0137",
    "CVE-2012-0138"
  );
  script_bugtraq_id(51903, 51904, 51906, 51907, 51908);
  script_osvdb_id(79254, 79255, 79256, 79257, 79258);
  script_xref(name:"MSFT", value:"MS12-015");

  script_name(english:"MS12-015: Vulnerabilities in Microsoft Visio Viewer 2010 Could Allow Remote Code Execution (2663510)");
  script_summary(english:"Checks the version of Vviewer.dll");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Visio Viewer.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Visio Viewer installed on the remote Windows
host is reportedly affected by several memory corruption
vulnerabilities due to the way the application handles memory when
parsing specially crafted Visio files.

An attacker who tricked a user on the affected host into opening a
specially crafted Visio file could leverage these issues to execute
arbitrary code in the context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-015");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Visio Viewer 2010.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visio_viewer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

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

bulletin = 'MS12-015';
kb = "2597170";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (!get_kb_item("SMB/WindowsVersion")) exit(1, "The 'SMB/WindowsVersion' KB item is missing.");
if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The 'SMB/Registry/Enumerated' KB item is missing.");

# Determine the install path for Vision Viewer 2010.
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

key = "SOFTWARE\Microsoft\Office\14.0\Common\InstallRoot";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Path");
  if (value) visio_viewer_path = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);


vuln = 0;


# Visio Viewer 2010.
if (visio_viewer_path)
{
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:visio_viewer_path);
  if (!is_accessible_share(share:share)) exit(1, "Can't access '"+share+"' share.");

  if (hotfix_check_fversion(path:visio_viewer_path, file:"Vviewer.dll", version:"14.0.6114.5001", min_version:"14.0.0.0", bulletin:bulletin, kb:kb) == HCF_OLDER) vuln++;
}


if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, "The host is not affected.");
}
