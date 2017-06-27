#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(40562);
 script_version("$Revision: 1.29 $");
 script_cvs_date("$Date: 2016/12/09 21:04:53 $");

 script_cve_id("CVE-2009-0562", "CVE-2009-2496", "CVE-2009-1136", "CVE-2009-1534");
 script_bugtraq_id(35642, 35990, 35991, 35992);
 script_osvdb_id(55806, 56914, 56915, 56916);
 script_xref(name:"IAVA", value:"2009-A-0069");
 script_xref(name:"MSFT", value:"MS09-043");
 script_xref(name:"Secunia", value:"35800");
 script_xref(name:"EDB-ID", value:"9163");
 script_xref(name:"EDB-ID", value:"16537");
 script_xref(name:"EDB-ID", value:"16542");

 script_name(english:"MS09-043: Vulnerabilities in Microsoft Office Web Components Could Allow Remote Code Execution (957638)");
 script_summary(english:"Determines the version of MSO.dll");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Office Web Components.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Office Web
Components that is affected by various flaws that may allow arbitrary
code to be run.

To succeed, the attacker would have to send specially crafted URLs to
a user of the remote computer and have him process it with Microsoft
Office Web Components.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-043");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office XP and 2003, as
well as for Microsoft ISA server.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Microsoft OWC Spreadsheet HTMLURL Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
 script_cwe_id(94, 119, 399);

 script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/13");
 script_set_attribute(attribute:"patch_publication_date", value:"2009/08/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:biztalk_server");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:isa_server");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_components");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio_.net");
 script_set_attribute(attribute:"stig_severity", value:"II");
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
include("smb_activex_func.inc");
include("misc_func.inc");
include("audit.inc");


get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS09-043';
kbs = make_list("947318", "947319", "947320", "947826", "968377", "969172");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


vuln = FALSE;
get_kb_item_or_exit('SMB/WindowsVersion');
path = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc");
if ( path )
{
  # This is MS ISA

  if (activex_init() != ACX_OK) exit(1, "Could not initialize the ActiveX checks");
  hcf_init = TRUE;

  # Test each control.
  info = NULL;
  clsids = make_list(
   "{0002E543-0000-0000-C000-000000000046}",
   "{0002E55B-0000-0000-C000-000000000046}"
  );

  foreach clsid (clsids)
  {
    file = activex_get_filename(clsid:clsid);
    if (file)
    {
      if (activex_get_killbit(clsid:clsid) == 0)
      {
        version = activex_get_fileversion(clsid:clsid);
        if (!version) version = "Unknown";

        info =
          '\n' +
          '  Class Identifier : ' + clsid + '\n' +
          '  Filename         : ' + file + '\n' +
          '  Version          : ' + version + '\n';
        if (!thorough_tests) break;
      }
    }
  }

  if (!isnull(info))
  {
    vuln = TRUE;
    hotfix_add_report(info, bulletin:bulletin, kb:'947826');
  }
  RegCloseKey(handle:_acx_hklm);
}

if (!path)
{
  login  = kb_smb_login();
  pass   = kb_smb_password();
  domain = kb_smb_domain();
  port   = kb_smb_transport();

  if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:'IPC$');
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL, "IPC$");
  }
  hcf_init = TRUE;
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

# Visual Studio .Net
vs_dll = NULL;
vs_path = NULL;
key = 'SOFTWARE\\Microsoft\\VisualStudio\\7.1';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:'InstallDir');
  if (!isnull(item))
  {
    rootfile = hotfix_get_programfilesdir();
    vs_dll = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1\\Microsoft Office\\Office\\msowc.dll', string:rootfile);
    vs_path = rootfile + '\\Microsoft Office\\Office';
  }
  RegCloseKey(handle:key_h);
}

# Microsoft Small Business Acounting 2006
sba_dll = NULL;
sba_path = NULL;
key = 'SOFTWARE\\Microsoft\\Small Business Accounting\\1.0\\InstallRoot';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:'Main');
  if (!isnull(item))
  {
    rootfiles = hotfix_get_officecommonfilesdir();
    checkeddirs = make_array();
    if (typeof(rootfiles) != 'array')
    {
      temp = rootfiles;
      rootfiles = make_array('commonfiles', temp);
    }
    foreach item (keys(rootfiles))
    {
      rootfile = rootfiles[item];
      if (checkeddirs[item]) continue;
      checkeddirs[item] = 1;
      sba_dll = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1\\Microsoft Shared\\Web Components', string:rootfile);
      sba_dll += '\\11\\Owc11.dll';
      sba_path = rootfile + '\\Microsoft Shared\\Web Components\\';
      break;
    }
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

# Office Suites and Office Web Components
office_ver = hotfix_check_office_version();
if (!is_accessible_share())
{
  if (vuln)
  {
    NetUseDel();
    hotfix_security_hole();
    exit(0);
  }
  else exit(1, 'is_accessible_share() failed.');
}

rootfile = hotfix_get_officeprogramfilesdir();

share = '';
lastshare = '';
if (rootfile && office_version)
{
  foreach ver (keys(office_version))
  {
    if (typeof(rootfiles) == 'array') rootfile = rootfiles[ver];
    else rootfile = rootfiles;
    info = NULL;
    path = NULL;
    kb = '';
    if (ver == "9.0")
    {
      dll = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1\\Microsoft Office\\Office\\msowc.dll', string:rootfile);
      path = rootfile + '\\Microsoft Office\\Office';
      kb = '947320';
    }
    else if (ver == "10.0")
    {
      dll = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1\\Microsoft Office\\Office10\\owc10.dll', string:rootfile);
      path = rootfile + '\\Microsoft Office\\Office10\\';
      kb = '947320';
    }
    else if (ver == "11.0")
    {
      rootfile = hotfix_get_officecommonfilesdir(officever:'11.0');
      dll = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1\\Microsoft Shared\\Web Components', string:rootfile);
      dll += '\\11\\Owc11.dll';
      path = rootfile + '\\Microsoft Shared\\Web Components\\';
      kb = '947319';
    }
    else if (ver == "12.0")
    {
      rootfile = hotfix_get_officecommonfilesdir(officever:'12.0');
      dll = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1\\Microsoft Shared\\Web Components', string:rootfile);
      dll += '\\11\\Owc11.dll';
      path = rootfile + '\\Microsoft Shared\\Web Components\\';
      kb = '947318';
    }

    if (path)
    {
      share = hotfix_path2share(path:path);
      if (share != lastshare)
      {
        lastshare = share;
        NetUseDel(close:FALSE);
        rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
        if (rc != 1)
        {
          audit(AUDIT_SHARE_FAIL, share);
        }
      }

      handle = CreateFile(
        file:dll,
        desired_access:GENERIC_READ,
        file_attributes:FILE_ATTRIBUTE_NORMAL,
        share_mode:FILE_SHARE_READ,
        create_disposition:OPEN_EXISTING
      );

      if (!isnull(handle))
      {
        ver = GetFileVersion(handle:handle);
        CloseFile(handle:handle);
        if (!isnull(ver))
        {
          version = join(ver, sep:'.');
          if (ver[0] == 9 && ver[1] == 0 && ver[2] == 0 && ver[3] < 8977)
          {
            info =
              '\n  Path              : ' + path +
              '\n  Installed version : ' + version +
              '\n  Fixed version     : 9.0.0.8977 \n';
          }
          else if (ver[0] == 10 && ver[1] == 0 && ver[2] < 6854)
          {
            info =
              '\n  Path              : ' + path +
              '\n  Installed version : ' + version +
              '\n  Fixed version     : 10.0.6854.0 \n';
          }
          else if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8304)
          {
            info =
              '\n  Path              : ' + path +
              '\n  Installed version : ' + version +
              '\n  Fixed version     : 11.0.8304.0 \n';
          }
          else if (ver[0] == 12 && ver[1] == 0 && (ver[2] < 6502 || (ver[2] == 6502 && ver[3] < 5000)))
          {
            info =
              '\n  Path              : ' + path +
              '\n  Installed version : ' + version +
              '\n  Fixed version     : 12.0.6502.5000 \n';
          }
        }
      }
    }
    if (info)
    {
      vuln = TRUE;
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
    }
  }
  NetUseDel(close:FALSE);
}
if (!vuln)
{
  # Multiple versions of Office Web Components can be installed separately
  # without installing office
  rootfile = NULL;
  rootfile = hotfix_get_commonfilesdir();

  if (rootfile)
  {
    rootfile += '\\Microsoft Shared\\Web Components\\';
    share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:'\\1$', string:rootfile);
    dirpat = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1\\*', string:rootfile);

    rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
    if (rc != 1)
    {
      audit(AUDIT_SHARE_FAIL, share);
    }

    owcdirs = make_list();
    fh = FindFirstFile(pattern:dirpat);
    while (!isnull(fh[1]))
    {
      if (fh[2] && FILE_ATTRIBUTE_DIRECTORY)
      {
        if (fh[1] =~ '^[0-9]+$')
        {
          owcdirs = make_list(owcdirs, fh[1]);
        }
      }
      fh = FindNextFile(handle:fh);
    }

    if (max_index(owcdirs) > 0)
    {
      for (i=0; i < max_index(owcdirs); i++)
      {
        info = NULL;
        path = rootfile + '\\' + owcdirs[i] + '\\';
        dll = ereg_replace(pattern:'[A-Za-z]:(.*)', replace:'\\1\\owc'+owcdirs[i]+'.dll', string:path);

        handle = CreateFile(
          file:dll,
          desired_access:GENERIC_READ,
          file_attributes:FILE_ATTRIBUTE_NORMAL,
          share_mode:FILE_SHARE_READ,
          create_disposition:OPEN_EXISTING
        );

        if (!isnull(handle))
        {
          ver = GetFileVersion(handle:handle);
          CloseFile(handle:handle);
          if (!isnull(ver))
          {
            version = join(ver, sep:'.');
            if (ver[0] == 10 && ver[1] == 0 && ver[2] < 6854)
            {
              info =
                '\n  Path              : ' + path +
                '\n  Installed version : ' + version +
                '\n  Fixed version     : 10.0.6854.0 \n';
            }
            else if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8304)
            {
              info =
                '\n  Path              : ' + path +
                '\n  Installed version : ' + version +
                '\n  Fixed version     : 11.0.8304.0 \n';
            }
            else if (ver[0] == 12 && ver[1] == 0 && (ver[2] < 6502 || (ver[2] == 6502 && ver[3] < 5000)))
            {
              info =
                '\n  Path              : ' + path +
                '\n  Installed version : ' + version +
                '\n  Fixed version     : 12.0.6502.5000 \n';
            }
          }
        }
        if (info)
        {
          vuln = TRUE;
          hotfix_add_report(info, bulletin:bulletin, kb:kb);
        }
      }
    }
    NetUseDel(close:FALSE);
  }
}
if (vs_dll || sba_dll)
{
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    audit(AUDIT_SHARE_FAIL, share);
  }
  if (vs_dll)
  {
    handle = CreateFile(
      file:vs_dll,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (!isnull(handle))
    {
      ver = GetFileVersion(handle:handle);
      CloseFile(handle:handle);
      if (!isnull(ver))
      {
        version = join(ver, sep:'.');
        if (ver[0] == 9 && ver[1] == 0 && ver[2] == 0 && ver[3] < 8977)
        {
          info =
            '\n  Path              : ' + vs_path +
            '\n  Installed version : ' + version +
            '\n  Fixed version     : 9.0.0.8977 \n';
          vuln = TRUE;
          hotfix_add_report(info, bulletin:bulletin, kb:'969172');
        }
      }
    }
  }
  if (sba_dll)
  {
    handle = CreateFile(
      file:sba_dll,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (!isnull(handle))
    {
      ver = GetFileVersion(handle:handle);
      CloseFile(handle:handle);
      if (!isnull(ver))
      {
        version = join(ver, sep:'.');
        if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8304)
        {
          info =
            '\n  Path              : ' + sba_path +
            '\n  Installed version : ' + version +
            '\n  Fixed version     : 11.0.8304 \n';
          vuln = TRUE;
          hotfix_add_report(info, bulletin:bulletin, kb:'968377');
        }
      }
    }
  }
}
NetUseDel();

if (vuln)
{
  set_kb_item(name:'SMB/Missing/MS09-043', value:TRUE);
  hotfix_security_hole();
  exit(0);
}
else exit(0, 'Host is patched.');
