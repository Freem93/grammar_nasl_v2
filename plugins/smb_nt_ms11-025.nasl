#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53382);
  script_version("$Revision: 1.29 $");
  script_cvs_date("$Date: 2016/05/06 17:11:38 $");

  script_cve_id("CVE-2010-3190");
  script_bugtraq_id(42811);
  script_osvdb_id(67674);
  script_xref(name:"MSFT", value:"MS11-025");
  script_xref(name:"IAVB", value:"2011-B-0046");
  script_xref(name:"Secunia", value:"41212");

  script_name(english:"MS11-025: Vulnerability in Microsoft Foundation Class (MFC) Library Could Allow Remote Code Execution (2500212)");
  script_summary(english:"Checks MFC library version");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the
Microsoft Foundation Class library.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of the Microsoft Foundation
Class (MFC) library affected by an insecure library loading
vulnerability. The path used for loading external libraries is not
securely restricted.

An attacker can exploit this by tricking a user into opening an MFC
application in a directory that contains a malicious DLL, resulting in
arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-025");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Visual Studio .NET 2003,
2005, and 2008, as well as Visual C++ 2005, 2008, and 2010.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_c++");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio_.net");
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
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");
get_kb_item_or_exit("SMB/Registry/Uninstall/Enumerated");

bulletin = 'MS11-025';
kbs = make_list("2467173", "2538242", "2538243", "2565057", "2565063", "2467174", "2467175");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

vuln = 0;

if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "KB 'SMB/Registry/Enumerated' not set to TRUE.");

arch = get_kb_item_or_exit("SMB/ARCH");

rootfile = hotfix_get_systemroot();
if (!rootfile) audit(AUDIT_PATH_NOT_DETERMINED, 'system root');

commonfiles = hotfix_get_commonfilesdir();
if (!commonfiles) audit(AUDIT_PATH_NOT_DETERMINED, 'Common Files');

MAX_RECURSE = 3;


port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

hcf_init = TRUE;

function _list_dir(basedir, level, dir_pat, file_pat)
{
  local_var contents, ret, subdirs, subsub;

  # nb: limit how deep we'll recurse.
  if (level > MAX_RECURSE) return NULL;

  subdirs = NULL;
  if (isnull(dir_pat)) dir_pat = "";
  ret = FindFirstFile(pattern:basedir + "\*" + dir_pat + "*");

  contents = make_list();
  while (!isnull(ret[1]))
  {
    if (file_pat && ereg(pattern:file_pat, string:ret[1], icase:TRUE))
      contents = make_list(contents, basedir+"\"+ret[1]);

    subsub = NULL;
    if ("." != ret[1] && ".." != ret[1] && level <= MAX_RECURSE)
      subsub  = _list_dir(basedir:basedir+"\"+ret[1], level:level+1, file_pat:file_pat);
    if (!isnull(subsub))
    {
      if (isnull(subdirs)) subdirs = make_list(subsub);
      else subdirs = make_list(subdirs, subsub);
    }
    ret = FindNextFile(handle:ret);
  }

  if (isnull(subdirs)) return contents;
  else return make_list(contents, subdirs);
}


# Returns the file version as a string, either from the KB or by
# calling GetFileVersion(). Assumes we're already connected to the
# correct share.
function _get_file_version()
{
  local_var fh, file, ver, version;

  if (isnull(_FCT_ANON_ARGS[0])) return NULL;

  file = _FCT_ANON_ARGS[0];
  version = get_kb_item("SMB/FileVersions"+tolower(str_replace(string:file, find:"\", replace:"/")));
  if (isnull(version))
  {
    fh = CreateFile(
      file:file,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (!isnull(fh))
    {
      ver = GetFileVersion(handle:fh);
      CloseFile(handle:fh);
      if (!isnull(ver))
      {
        version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
        set_kb_item(
          name:"SMB/FileVersions"+tolower(str_replace(string:file, find:"\", replace:"/")),
          value:version
        );
      }
    }
  }
  return version;
}


#######################################################################
# Check VC++ Redistributables.
#######################################################################
installs = make_array();

# - Check if the redistributable is known to be installed; otherwise,
#   we'll generate a false positive against Visual Studio.
list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (!isnull(list))
{
  foreach name (keys(list))
  {
    prod = list[name];
    if (prod && ereg(pattern:"^Microsoft Visual C\+\+ 200[58] Redistributable", string:prod, icase:TRUE))
    {
      installs[tolower(prod)]++;
    }
    # 2010 is treated differently since it doesn't appear to drop anything in the winsxs directory
    else if (prod && ereg(pattern:"^Microsoft Visual C\+\+ 2010 .+Redistributable", string:prod, icase:TRUE))
    {
      vcpp2010_installed = TRUE;
    }
  }
}

if (max_index(keys(installs)) || vcpp2010_installed)
{
  fixed = make_array();
  probs = make_array();
  kbs = make_array();
  fixed_versions = make_array();
  fversions = make_array();

  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
  if (!is_accessible_share(share:share)) exit(1, "Can't access '"+share+"' share.");

  # first check VC++ 2010
  if (
    vcpp2010_installed &&
    (hotfix_is_vulnerable(file:"mfc100.dll", dir:"\system32", bulletin:bulletin, kb:"2467173", version:"10.0.30319.415", min_version:"10.0.0.0") ||
     hotfix_is_vulnerable(file:"mfc100.dll", dir:"\system32", bulletin:bulletin, kb:"2565063", version:"10.0.40219.325", min_version:"10.0.40000.0"))
  )
  {
    # blank out any plugin output created by hotfix_is_vulnerable() so
    # 2010 is reported the same way as 2005 and 2008
    hcf_report = NULL;

    path = tolower(rootfile + "\system32\mfc100.dll") - ':';
    kb_key = 'SMB/FileVersions/' + str_replace(string:path, find:'\\', replace:'/');
    vc2010_version = get_kb_item(kb_key);

    if (vc2010_version =~ "^10\.0\.4")
    {
      vc2010_prodname = 'Visual C++ 2010 SP1 Redistributable Package';
      kbs[vc2010_prodname] = '2565063';
      fixed_versions[vc2010_prodname] = '10.0.40219.325';
    }
    else
    {
      vc2010_prodname = 'Visual C++ 2010 Redistributable Package';
      kbs[vc2010_prodname] = '2467173';
      fixed_versions[vc2010_prodname] = '10.0.30319.415';
    }

    fversions[vc2010_prodname] = vc2010_version;
    probs[vc2010_prodname] = 1;
    vuln++;
  }

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL, share);
  }

  # Then check the winsxs dir for 2005 and 2008
  winsxs = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\WinSxS", string:rootfile);
  files = _list_dir(basedir:winsxs, level:0, dir_pat:"microsoft.vc?0.mfc", file_pat:"^mfc(80|90)\.dll$");
  if (!isnull(files))
  {
    foreach file (files)
    {
      if (ereg(pattern:"Microsoft\.VC80\.MFC", string:file, icase:TRUE))
      {
        prod = '';
        if ('x86' >< file) prod = "Visual C++ 2005 SP1 Redistributable Package 32-bit";
        else if ('amd64' >< file && arch == 'x64') prod = "Visual C++ 2005 SP1 Redistributable Package 64-bit";
        if (prod)
        {
          fixed_versions[prod] = "8.0.50727.6195";
          kbs[prod] = '2538242';
        }
      }
      else if (ereg(pattern:"Microsoft\.VC90\.MFC.+_9\.0\.3[0-9]+", string:file, icase:TRUE))
      {
        prod = '';
        if ('x86' >< file) prod = "Visual C++ 2008 SP1 Redistributable Package 32-bit";
        else if ('amd64' >< file && arch == 'x64') prod = "Visual C++ 2008 SP1 Redistributable Package 64-bit";
        if (prod)
        {
          fixed_versions[prod] = "9.0.30729.6161";
          kbs[prod] = '2538243';
        }
      }
      else continue;

      installed = FALSE;

      # only consider VC++ to be installed if it shows up in the registry AND the winsxs dir
      foreach key (keys(installs))
      {
        if (
          ((" 2005 " >< prod && "32-bit" >< prod) && (" 2005 " >< key && "(x64)" >!< key)) ||
          ((" 2005 " >< prod && "64-bit" >< prod) && (" 2005 " >< key && "(x64)" >< key)) ||
          ((" 2008 " >< prod && "32-bit" >< prod) && (" 2008 " >< key && " x86 " >< key)) ||
          ((" 2008 " >< prod && "64-bit" >< prod) && (" 2008 " >< key && " x64 " >< key)) ||
          (" 2010 " >< prod && " 2010 " >< key)
        )
        {
          installed = TRUE;
          break;
        }
      }
      if (!installed) continue;

      if (isnull(fixed[prod]) || fixed[prod] == 0)
      {
        version = _get_file_version(file);
        fversions[prod] = version;
        if (!isnull(version))
        {
          ver = split(version, sep:'.', keep:FALSE);
          for (i=0; i<max_index(ver); i++)
            ver[i] = int(ver[i]);

          fix = split(fixed_versions[prod], sep:'.', keep:FALSE);
          for (i=0; i<max_index(fix); i++)
            fix[i] = int(fix[i]);

          # Flag it if it's older or flag the fix if it's fixed.
          if (ver[0] == fix[0] && ver[1] == fix[1] && ver[2] == fix[2])
          {
            if (ver[3] < fix[3])
            {
              probs[prod]++;
            }
            else
            {
              fixed[prod]++;
              probs[prod] = 0;
            }
          }
        }
      }
    }
  }
  NetUseDel(close:FALSE);

  # Report and exit if there's a problem.
  report = NULL;
  vccvulns = 0;

  foreach prod (keys(probs))
  {
    if (!fixed[prod]) vccvulns++;
  }
  if (vccvulns)
  {
    if (vccvulns > 1) s = "s have";
    else s = " has";

    report =
      '\nThe following Visual C++ Redistributable Package'+ s +' not'+
      '\nbeen patched : \n';
    hotfix_add_report(report);
    foreach prod (keys(probs))
    {
      if (fixed[prod]) continue;

      info = "";
      info =
        '\n  Product           : ' + prod +
        '\n  Installed version : ' + fversions[prod] +
        '\n  Fixed version     : ' + fixed_versions[prod] + '\n';
      hotfix_add_report(info, bulletin:bulletin, kb:kbs[prod]);
    }
    vuln++;
  }
}



#######################################################################
# Check Visual Studio installs.
#######################################################################
# - identify VCROOT for each install.
installs = make_array();

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

key = "SOFTWARE\Microsoft\VisualStudio";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (report_paranoia < 2) pat = "^(7\.1|8\.0|9\.0|10\.0)$";
    else pat = "^[0-9]\.[0-9]+$";
    if (strlen(subkey) && ereg(pattern:pat, string:subkey))
    {
      key2 = key + "\" + subkey;
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        item2 = RegQueryValue(handle:key2_h, item:"InstallDir");
        if (!isnull(item2))
        {
          path = item2[1];
          path = ereg_replace(pattern:'^"(.+)"$', replace:"\1", string:path);

          vcroot = ereg_replace(pattern:"^(.+)\\Common7\\IDE\\$", replace:"\1", string:path, icase:TRUE);
          if (vcroot >< path) installs[subkey] = vcroot;
        }
        RegCloseKey(handle:key2_h);
      }
    }
  }
  RegCloseKey(handle:key_h);
}
# Check wow6432 node
key = "SOFTWARE\Wow6432Node\Microsoft\VisualStudio";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (report_paranoia < 2) pat = "^(7\.1|8\.0|9\.0|10\.0)$";
    else pat = "^[0-9]\.[0-9]+$";
    if (strlen(subkey) && ereg(pattern:pat, string:subkey))
    {
      key2 = key + "\" + subkey;
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        item2 = RegQueryValue(handle:key2_h, item:"InstallDir");
        if (!isnull(item2))
        {
          path = item2[1];
          path = ereg_replace(pattern:'^"(.+)"$', replace:"\1", string:path);

          vcroot = ereg_replace(pattern:"^(.+)\\Common7\\IDE\\$", replace:"\1", string:path, icase:TRUE);
          if (vcroot >< path) installs[subkey] = vcroot;
        }
        RegCloseKey(handle:key2_h);
      }
    }
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);


# - locate possibly-affected files.
mfc_files = make_list();

foreach ver (keys(installs))
{
  if (ver =~ "^([89]|10)\.")
  {
    vcroot = installs[ver];

    share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:vcroot);
    rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
    if (rc != 1)
    {
      NetUseDel();
      audit(AUDIT_SHARE_FAIL, share);
    }

    path =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:vcroot);
    files = _list_dir(basedir:path+"\VC\redist", level:0, file_pat:"^mfc(80|90|100)\.dll$");
    if (!isnull(files))
    {
      foreach file (files)
      {
        mfc_files = make_list(mfc_files, (share-'$')+':'+file);
      }
    }
  }
  else
  {
    if (report_paranoia < 2) pat = "^mfc(71|80|90|100)\.dll$";
    else pat = "^mfc[0-9]+\.dll$";

    basedirs = make_list(
      rootfile+"\System32",
      commonfiles+"\Microsoft Shared\Help",
      commonfiles+"\Microsoft Shared\VSA"
    );

    foreach basedir (basedirs)
    {
      share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:basedir);
      rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
      if (rc != 1)
      {
        NetUseDel();
        audit(AUDIT_SHARE_FAIL, share);
      }
      basedir = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:basedir);

      if (ereg(pattern:"\System32$", string:basedir, icase:TRUE))
        files = _list_dir(basedir:basedir, level:MAX_RECURSE, file_pat:pat);
      else
        files = _list_dir(basedir:basedir, level:0, file_pat:pat);
      if (!isnull(files))
      {
        foreach file (files)
        {
            mfc_files = make_list(mfc_files, (share-'$')+':'+file);
        }
      }
      NetUseDel(close:FALSE);
    }
  }
}
NetUseDel(close:FALSE);


# - check each file.
foreach mfc (mfc_files)
{
  match = eregmatch(pattern:"^(.+)\\(mfc[0-9]+\.dll)$", string:mfc, icase:TRUE);
  if (match)
  {
    path = match[1];
    file = match[2];

    if (
      hotfix_check_fversion(file:file, path:path, bulletin:bulletin, kb:"2565057", version:"10.0.40219.325", min_version:"10.0.40000.0") == HCF_OLDER ||
      hotfix_check_fversion(file:file, path:path, bulletin:bulletin, kb:"2542054", version:"10.0.30319.460", min_version:"10.0.0.0") == HCF_OLDER ||
      hotfix_check_fversion(file:file, path:path, bulletin:bulletin, kb:"2538241", version:"9.0.30729.6161", min_version:"9.0.0.0") == HCF_OLDER ||
      hotfix_check_fversion(file:file, path:path, bulletin:bulletin, kb:"2538218", version:"8.0.50727.6195", min_version:"8.0.0.0") == HCF_OLDER ||
      hotfix_check_fversion(file:file, path:path, bulletin:bulletin, kb:"2465373", version:"7.10.6119.0") == HCF_OLDER
    ) vuln++;
  }
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
