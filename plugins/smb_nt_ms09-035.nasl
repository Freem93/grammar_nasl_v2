#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40435);
  script_version("$Revision: 1.29 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id("CVE-2009-0901", "CVE-2009-2493", "CVE-2009-2495");
  script_bugtraq_id(35828, 35830, 35832);
  script_osvdb_id(56696, 56698, 56699);
  script_xref(name:"MSFT", value:"MS09-035");
  script_xref(name:"IAVB", value:"2009-B-0033");
  script_xref(name:"CERT", value:"456745");

  script_name(english:"MS09-035: Vulnerabilities in Visual Studio Active Template Library Could Allow Remote Code Execution (969706)");
  script_summary(english:"Checks for Visual Studio / Visual C++ patches");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Active Template Library.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of the Microsoft Active
Template Library (ATL), included as part of Visual Studio or Visual
C++, that is affected by multiple vulnerabilities :

  - On systems with components and controls installed that
    were built using Visual Studio ATL, an issue in the ATL
    headers could allow an attacker to force VariantClear
    to be called on a VARIANT that has not been correctly
    initialized and, by supplying a corrupt stream, to
    execute arbitrary code. (CVE-2009-0901)

  - On systems with components and controls installed that
    were built using Visual Studio ATL, unsafe usage of
    OleLoadFromStream could allow instantiation of
    arbitrary objects that can bypass related security
    policy, such as kill bits within Internet Explorer.
    (CVE-2009-2493)

  - On systems with components and controls installed that
    were built using Visual Studio ATL, an issue in the ATL
    headers could allow a string to be read without a
    terminating NULL character, which could lead to
    disclosure of information in memory. (CVE-2009-2495)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-035");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Visual Studio .NET 2003,
Visual Studio 2005 and 2008, as well as Visual C++ 2005 and 2008.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94, 200, 264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio_.net");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_c++");
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
include("smb_reg_query.inc");
include("misc_func.inc");
include("audit.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");
get_kb_item_or_exit("SMB/Registry/Uninstall/Enumerated");

bulletin = 'MS09-035';
kbs = make_list("973544", "973551", "973552", "973675");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


if (!get_kb_item("SMB/WindowsVersion")) exit(1, "SMB/WindowsVersion KB item is missing.");


rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Can't get system root.");

commonfiles = hotfix_get_commonfilesdir();

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
function get_file_version()
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
  }
}

if (max_index(keys(installs)))
{
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
  if (!is_accessible_share(share:share)) exit(1, "Can't access '"+share+"' share.");

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, "Can't access '"+share+"' share.");
  }

  fixed = make_array();
  probs = make_array();
  kbs = make_array();
  fixed_versions = make_array();
  fversions = make_array();
  prodfiles = make_array();

  winsxs = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\WinSxS", string:rootfile);
  files = _list_dir(basedir:winsxs, level:0, dir_pat:"microsoft.vc?0.atl", file_pat:"^atl(80|90)\.dll$");
  if (!isnull(files))
  {
    foreach file (files)
    {
      if (ereg(pattern:"Microsoft\.VC80\.ATL", string:file, icase:TRUE))
      {
        prod = "Visual C++ 2005 SP1 Redistributable Package";
        fixed_versions[prod] = "8.0.50727.4053";
        prodfiles[prod] = "atl80.dll";
        kbs[prod] = '973544';
      }
      else if (ereg(pattern:"Microsoft\.VC90\.ATL.+_9\.0\.[0-2][0-9]+", string:file, icase:TRUE))
      {
        prod = "Visual C++ 2008 Redistributable Package";
        fixed_versions[prod] = "9.0.21022.218";
        prodfiles[prod] = "atl90.dll";
        kbs[prod] = '973551';
      }
      else if (ereg(pattern:"Microsoft\.VC90\.ATL.+_9\.0\.3[0-9]+", string:file, icase:TRUE))
      {
        prod = "Visual C++ 2008 SP1 Redistributable Package";
        fixed_versions[prod] = "9.0.30729.4148";
        prodfiles[prod] = "atl90.dll";
        kbs[prod] = '973552';
      }
      else continue;

      installed = FALSE;
      foreach key (keys(installs))
      {
        if (
          (" 2005 " >< prod && " 2005 " >< key) ||
          (
            " 2008 " >< prod && " 2008 " >< key &&
            (
              ereg(pattern:" 9\.0\.[0-2][0-9]+", string:key) ||
              (" SP1 " >< prod && ereg(pattern:" 9\.0\.3[0-9]+", string:key))
            )
          )
        )
        {
          installed = TRUE;
          break;
        }
      }
      if (!installed) continue;

      if (isnull(fixed[prod]) || fixed[prod] == 0)
      {
        version = get_file_version(file);
        fversions[prod] = version;
        if (!isnull(version))
        {
          if (version == fixed_versions[prod])
          {
            fixed[prod]++;
            if (prod == "Visual C++ 2008 SP1 Redistributable Package")
            {
              fixed["Visual C++ 2008 Redistributable Package"]++;
              probs[prod] = 0;
            }
            continue;
          }

          ver = split(version, sep:'.', keep:FALSE);
          for (i=0; i<max_index(ver); i++)
            ver[i] = int(ver[i]);

          fix = split(fixed_versions[prod], sep:'.', keep:FALSE);
          for (i=0; i<max_index(fix); i++)
            fix[i] = int(fix[i]);

          # Flag it if it's older or flag the fix if it's fixed.
          for (i=0; i<max_index(ver); i++)
            if ((ver[i] < fix[i]))
            {
              fixed[prod] = 0;
              probs[prod]++;
              break;
            }
            else if (ver[i] > fix[i])
            {
              fixed[prod]++;
              probs[prod] = 0;
              if (prod == "Visual C++ 2008 SP1 Redistributable Package")
              {
                fixed["Visual C++ 2008 Redistributable Package"]++;
                probs[prod] = 0;
              }
              break;
            }
          }
      }
    }
  }
  NetUseDel(close:FALSE);

  # Report and exit if there's a problem.
  info = "";
  s = 0;
  foreach prod (keys(probs))
  {
    if (!fixed[prod]) s++;
  }
  if (s)
  {
    set_kb_item(name:'SMB/Missing/MS09-035', value:TRUE);

    if (s > 1) s = 's have';
    else s = ' has';
    info =
      '\n  The following Visual C++ Redistributable Package' + s + ' not' +
      '\n  been patched : \n';
    hotfix_add_report(info);
    foreach prod (keys(probs))
    {
      if (fixed[prod]) continue;

      info =
        '\n  Product           : ' + prod +
        '\n  File              : ' + prodfiles[prod] +
        '\n  Installed version : ' + fversions[prod] +
        '\n  Fixed version     : ' + fixed_versions[prod] + '\n';
      hotfix_add_report(info, bulletin:bulletin, kb:kbs[prod]);
    }
    hotfix_security_hole();
    exit(0);
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
  exit(1, "Can't connect to IPC$ share.");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
}

key = "SOFTWARE\Microsoft\VisualStudio";
subkeys = get_registry_subkeys(handle:hklm, key:key, wow:TRUE);
if (!isnull(subkeys))
{
  if (report_paranoia < 2) pat = '^(7\\.1|8\\.0|9\\.0)$';
  else pat = '^[0-9]\\.[0-9]+$';
  foreach node (keys(subkeys))
  {
    key = node;
    foreach subkey (subkeys[node])
    {
      if (ereg(pattern:pat, string:subkey))
      {
        key2 = key + '\\' + subkey;
        path = get_registry_value(handle:hklm, item:key2 + "\InstallDir");
        if (!isnull(path))
        {
          path = ereg_replace(pattern:'^"(.+)"$', replace:"\1", string:path);
          vcroot = ereg_replace(pattern:"^(.+)\\Common7\\IDE\\$", replace:"\1", string:path, icase:TRUE);
          if (vcroot >< path) installs[subkey] = vcroot;
        }
      }
    }
  }
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

# - locate possibly-affected files.
atl_files = make_list();

foreach ver (keys(installs))
{
  if (ver =~ "^[89]\.")
  {
    vcroot = installs[ver];

    share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:vcroot);
    rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
    if (rc != 1)
    {
      NetUseDel();
      exit(1, "Can't access '"+share+"' share.");
    }

    path =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:vcroot);
    files = _list_dir(basedir:path+"\VC\redist", level:0, file_pat:"^atl(80|90)\.dll$");
    if (!isnull(files))
    {
      foreach file (files)
      {
        atl_files = make_list(atl_files, (share-'$')+':'+file);
      }
    }
  }
  else
  {
    if (report_paranoia < 2) pat = "^atl(71|80|90)\.dll$";
    else pat = "^atl[0-9][0-9]\.dll$";

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
        exit(1, "Can't access '"+share+"' share.");
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
            atl_files = make_list(atl_files, (share-'$')+':'+file);
        }
      }
      NetUseDel(close:FALSE);
    }
  }
}
NetUseDel(close:FALSE);


# - check each file.
vuln = 0;

foreach atl (atl_files)
{
  match = eregmatch(pattern:"^(.+)\\(atl[0-9]+\.dll)$", string:atl, icase:TRUE);
  if (match)
  {
    path = match[1];
    file = match[2];

    if (
      hotfix_check_fversion(file:file, version:"9.0.30729.4148", min_version:"9.0.30000.0", path:path, bulletin:bulletin, kb:'973675') == HCF_OLDER ||
      hotfix_check_fversion(file:file, version:"9.0.21022.218",  min_version:"9.0.0.0",     path:path, bulletin:bulletin, kb:'973674') == HCF_OLDER ||
      hotfix_check_fversion(file:file, version:"8.0.50727.4053", min_version:"8.0.0.0",     path:path, bulletin:bulletin, kb:'971090') == HCF_OLDER ||
      hotfix_check_fversion(file:file, version:"7.10.6101.0",                               path:path, bulletin:bulletin, kb:'971089') == HCF_OLDER
    ) vuln++;
  }
}

if (vuln)
{
  set_kb_item(name:"SMB/Missing/MS09-035", value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, "The host is not affected");
}
