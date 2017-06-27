#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45021);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/07/07 15:05:40 $");

  script_cve_id(
    "CVE-2010-0257",
    "CVE-2010-0258",
    "CVE-2010-0260",
    "CVE-2010-0261",
    "CVE-2010-0262",
    "CVE-2010-0263",
    "CVE-2010-0264"
  );
  script_bugtraq_id(38547, 38550, 38551, 38552, 38553, 38554, 38555);
  script_osvdb_id(62817, 62818, 62819, 62820, 62821, 62822, 62823);
  script_xref(name:"MSFT", value:"MS10-017");

  script_name(english:"MS10-017: Vulnerabilities in Microsoft Office Excel Could Allow Remote Code Execution (980150)");
  script_summary(english:"Checks version of Excel et al.");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Office Excel.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a version of Microsoft Office Excel 2002,
Microsoft Office Excel 2003, Microsoft Office Excel 2007, Microsoft
Office Excel Viewer, or Microsoft Office Compatibility Pack that is
affected by several vulnerabilities.

If an attacker can trick a user on the affected system into opening a
specially crafted Excel file using the affected application, he may be
able to leverage this issue to execute arbitrary code subject to the
user's privileges.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-017");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office Excel 2002, Office
Excel 2003, Excel 2007, Office Excel Viewer and Office Compatibility
Pack.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_nt_ms02-031.nasl", "office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}


include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("audit.inc");

include("misc_func.inc");
get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS10-017';
kbs = make_list("978380", "978382", "978383", "978471", "978474", "979439");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/WindowsVersion");

info = "";


# Excel.
vuln = 0;
installs = get_kb_list("SMB/Office/Excel/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/Excel/' - '/ProductPath';
    path = installs[install];

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    # Excel 2007.
    if (
      ver[0] == 12 && ver[1] == 0 &&
      (
        ver[2] < 6524 ||
        (ver[2] == 6524 && ver[3] < 5003)
      )
    )
    {
      office_sp = get_kb_item("SMB/Office/2007/SP");
      if (!isnull(office_sp) && (office_sp == 1 || office_sp == 2))
      {
        vuln++;
        kb = "978382";

        info =
          '\n  Product           : Excel 2007' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 12.0.6524.5003\n';
        hotfix_add_report(info, bulletin:bulletin, kb:kb);
      }
    }
    # Excel 2003.
    else if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8320)
    {
      office_sp = get_kb_item("SMB/Office/2003/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        vuln++;
        kb = "978474";

        info =
          '\n  Product           : Excel 2003' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 11.0.8320.0\n';
        hotfix_add_report(info, bulletin:bulletin, kb:kb);
      }
    }
    # Excel 2002.
    else if (ver[0] == 10 && ver[1] == 0 && ver[2] < 6860)
    {
      office_sp = get_kb_item("SMB/Office/XP/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        vuln++;
        kb = "978471";

        info =
          '\n  Product           : Excel 2002' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 10.0.6860.0\n';
        hotfix_add_report(info, bulletin:bulletin, kb:kb);
      }
    }
  }
}


# Excel Viewer.
installs = get_kb_list("SMB/Office/ExcelViewer/*/ProductPath");
if(!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/ExcelViewer/' - '/ProductPath';
    path = installs[install];

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    # Excel Viewer.
    if (
      ver[0] == 12 && ver[1] == 0 &&
      (
        ver[2] < 6524 ||
        (ver[2] == 6524 && ver[3] < 5003)
      )
    )
    {
      vuln++;
      kb = "978383";

      info =
        '\n  Product           : Excel Viewer' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 12.0.6524.5003\n';
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
    }
  }
}


# 2007 Microsoft Office system and the Microsoft Office Compatibility Pack.
installs = get_kb_list("SMB/Office/ExcelCnv/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/ExcelCnv/' - '/ProductPath';
    path = installs[install];

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    # 2007 Office system and the Office Compatibility Pack.
    if (
      ver[0] == 12 && ver[1] == 0 &&
      (
        ver[2] < 6529 ||
        (ver[2] == 6529 && ver[3] < 5000)
      )
    )
    {
      vuln++;
      kb = "978380";

      info =
        '\n  Product           : 2007 Office system and the Office Compatibility Pack' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 12.0.6529.5000\n';
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
    }
  }
}


# Excel Services in SharePoint Server 2007.

# - first, figure out where it's installed or *might be* installed.
sps2007_path = NULL;

port    = kb_smb_transport();
login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");


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

key = "SOFTWARE\Microsoft\Office Server\12.0";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"InstallPath");
  if (!isnull(item))
  {
    sps2007_path = item[1];
    sps2007_path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:sps2007_path);
  }

  RegCloseKey(handle:key_h);
}
if (isnull(sps2007_path)) sps2007_path = hotfix_get_programfilesdir() + "\Microsoft Office Servers\12.0";

RegCloseKey(handle:hklm);
NetUseDel();

# - now look at its version.
arch = get_kb_item("SMB/ARCH");
if (isnull(arch)) exit(1, "The 'SMB/ARCH' KB item is missing.");

sps2007_path += "\bin";
if (
  # - 32-bit editions
  (
    arch == "x86" &&
    # nb: KB 979439 says the version should be 12.0.6527.5000, but the patch says otherwise.
    hotfix_check_fversion(path:sps2007_path, file:"Xlsrv.dll", version:"12.0.6524.5003", min_version:"12.0.0.0", bulletin:bulletin, kb:"979439") == HCF_OLDER
  ) ||
  # - 64-bit editions
  (
    arch != "x86" &&
    hotfix_check_fversion(path:sps2007_path, file:"Xlsrv.dll", version:"12.0.6524.5003", min_version:"12.0.0.0", bulletin:bulletin, kb:"979439") == HCF_OLDER
  )
)
{
  vuln++;
}
if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
