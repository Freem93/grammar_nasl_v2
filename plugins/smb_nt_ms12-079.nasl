#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63226);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id("CVE-2012-2539");
  script_bugtraq_id(56834);
  script_osvdb_id(88315);
  script_xref(name:"MSFT", value:"MS12-079");
  script_xref(name:"IAVA", value:"2012-A-0194");

  script_name(english:"MS12-079: Vulnerability in Microsoft Word Could Allow Remote Code Execution (2780642)");
  script_summary(english:"Checks file versions");

  script_set_attribute(attribute:"synopsis", value:
"A Microsoft Office component installed on the remote host is affected
by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Office, Office Compatibility Pack, Microsoft Word
Viewer, Microsoft Office Web Apps, and/or Microsoft Share Point Server
installed on the remote host has a remote code execution
vulnerability. This is due to the way that Microsoft Office software
parses RTF data and could allow an attacker to execute arbitrary code
by tricking a user into opening a specially crafted RTF file.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS12-079");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2003, 2007, 2010,
Office Compatibility Pack, Microsoft Word Viewer, Microsoft Office Web
Apps and Microsoft SharePoint Server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");

  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_nt_ms02-031.nasl", "office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

global_var bulletin, vuln;

function get_ver()
{
  local_var fh, path, rc, share, ver;

  path = _FCT_ANON_ARGS[0];

  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);

  rc = NetUseAdd(share:share);
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL, share);
  }

  ver = NULL;
  path = ereg_replace(string:path, pattern:"^[A-Za-z]:(.*)", replace:"\1\");

  fh = CreateFile(
    file               : path,
    desired_access     : GENERIC_READ,
    file_attributes    : FILE_ATTRIBUTE_NORMAL,
    share_mode         : FILE_SHARE_READ,
    create_disposition : OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    ver = GetFileVersion(handle:fh);
    ver = join(ver, sep:".");
    CloseFile(handle:fh);
  }

  NetUseDel(close:FALSE);

  return ver;
}

function check_vuln(fix, kb, name, path, ver)
{
  local_var info;

  if (isnull(ver))
    ver = get_ver(path);

  if (isnull(ver) || ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
    return 0;

  info =
    '\n  Product           : ' + name +
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
  hotfix_add_report(info, bulletin:bulletin, kb:kb);

  vuln = TRUE;
}

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS12-079';
kbs = make_list(
  2760405, 2760410, 2687412, 2760416,
  2760421, 2760497, 2760498
);
if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

# Connect to the registry.
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# Get path information for SharePoint Server 2010
sps_2010_path = get_registry_value(
  handle : hklm,
  item   : "SOFTWARE\Microsoft\Office Server\14.0\InstallPath"
);

# Close connection to registry.
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

# SharePoint Server 2010 and Office Web Apps
if (sps_2010_path)
{
  # SharePoint
  check_vuln(
    name : "Office SharePoint Server 2010",
    kb   : "2760405",
    path : sps_2010_path + "WebServices\WordServer\Core\sword.dll",
    fix  : "14.0.6129.5000"
  );

  # Office Web Apps
  check_vuln(
    name : "Office Web Apps 2010",
    kb   : "2687412",
    path : sps_2010_path + "WebServices\ConversionService\Bin\Converter\sword.dll",
    fix  : "14.0.6129.5000"
  );
}

# Word
kb = "";
installs = get_kb_list("SMB/Office/Word/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/Word/' - '/ProductPath';
    path = installs[install];
    info = "";


    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

    # Word 2010
    if (
      ver[0] == 14 && ver[1] == 0 &&
      (
        ver[2] < 6129 ||
        (ver[2] == 6129 && ver[3] < 5000)
      )
    )
    {
      office_sp = get_kb_item("SMB/Office/2010/SP");
      if (!isnull(office_sp) && office_sp == 1)
      {
        info =
          '\n  Product           : Word 2010' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 14.0.6129.5000' + '\n';
        kb = "2760410";
      }
    }

    # Word 2007
    if (
      ver[0] == 12 && ver[1] == 0 &&
      (
        ver[2] < 6668 ||
        (ver[2] == 6668 && ver[3] < 5000)
      )
    )
    {
      office_sp = get_kb_item("SMB/Office/2007/SP");
      if (!isnull(office_sp) && (office_sp == 2 || office_sp == 3))
      {
        info =
          '\n  Product           : Word 2007' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 12.0.6668.5000' + '\n';
        kb = "2760421";
      }
    }

    # Word 2003
    if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8350)
    {
      office_sp = get_kb_item("SMB/Office/2003/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        info =
          '\n  Product           : Word 2003' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 11.0.8350.0' + '\n';
        kb = "2760497";
      }
    }

    if (info)
    {
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
      vuln = TRUE;
    }
  }
}

# Word Viewer
installs = get_kb_list("SMB/Office/WordViewer/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    info = "";
    version = install - 'SMB/Office/WordViewer/' - '/ProductPath';
    path = installs[install];
    if (isnull(path)) path = "n/a";

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

    if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8350)
    {
      info =
        '\n  Product           : Word Viewer' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 11.0.8350.0' + '\n';
      kb = "2760498";
    }

    if (info)
    {
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
      vuln = TRUE;
      break;
    }
  }
}

# 2007 Microsoft Office system and the Microsoft Office Compatibility Pack.
list = get_kb_list("SMB/Office/WordViewer/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    info = "";
    version = install - 'SMB/Office/WordCnv/' - '/ProductPath';
    path = installs[install];

    if (path)
    {
      share = hotfix_path2share(path:path);
      if (!is_accessible_share(share:share))
        audit(AUDIT_SHARE_FAIL, share);

      path = path - '\\Wordconv.exe';

      old_report = hotfix_get_report();
      check_file = "wordcnv.dll";

      if (hotfix_check_fversion(path:path, file:check_file, version:"12.0.6668.5000") == HCF_OLDER)
      {
        file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1\" + check_file);
        kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
        version = get_kb_item(kb_name);

        info =
          '\n  Product           : Microsoft Office Compatibility Pack for Word, Excel, and PowerPoint 2007 File Formats' +
          '\n  File              : ' + path + '\\' + check_file +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 12.0.6668.5000' + '\n';

        hcf_report = '';
        hotfix_add_report(old_report + info, bulletin:bulletin, kb:"2760416");
        vuln = TRUE;
      }
    }
  }

  hotfix_check_fversion_end();
}

if (vuln)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  exit(0);
}
else
{
  audit(AUDIT_HOST_NOT, 'affected');
}
