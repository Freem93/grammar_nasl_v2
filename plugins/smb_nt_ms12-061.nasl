#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62043);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/12/01 15:02:06 $");

  script_cve_id("CVE-2012-1892");
  script_bugtraq_id(55409);
  script_osvdb_id(85315);
  script_xref(name:"MSFT", value:"MS12-061");
  script_xref(name:"IAVB", value:"2012-B-0090");

  script_name(english:"MS12-061: Vulnerability in Visual Studio Team Foundation Server Could Allow Elevation of Privilege (2719584)");
  script_summary(english:"Checks version of Microsoft.TeamFoundation.WebAccess.Server.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Visual Studio Team
Foundation Server 2010 that is affected by a cross-site scripting
vulnerability. An attacker who successfully exploited this
vulnerability could take any action that the targeted user could take
on the site.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-061");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Visual Studio Team
Foundation Server 2010 SP1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio_team_foundation_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "microsoft_team_foundation_server_installed.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('audit.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('misc_func.inc');

appname = 'Microsoft Team Foundation Server';

global_var bulletin, vuln;

kb_base = "SMB/Microsoft_Team_Foundation_Server/";
bulletin = "MS12-061";
kbs = make_list(2719584);

vuln = FALSE;

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

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

# Check if we can connect to the registry.
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

# Get path information for Windows.
windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, "Failed to determine the location of %windir%.");

num_installed = get_kb_item_or_exit(kb_base + 'NumInstalled');

for (install_num = 0; install_num < num_installed; install_num++)
{
  path = get_kb_item_or_exit(kb_base + install_num + '/Path');
  version = get_kb_item_or_exit(kb_base + install_num + '/Version');

  if (version == '10.0.40219.1') # 2010 SP1
  {
    share = ereg_replace(string:windir, pattern:"^([A-Za-z]):.*", replace:"\1$");
    rc = NetUseAdd(share:share);
    if (rc != 1)
    {
      NetUseDel();
      audit(AUDIT_SHARE_FAIL, share);
    }

    dir = ereg_replace(string:windir, pattern:"^[A-Za-z]:(.*)", replace:"\1");
    subdir = "\assembly\GAC_MSIL\Microsoft.TeamFoundation.WebAccess.Server\";
    file = "Microsoft.TeamFoundation.WebAccess.Server.dll";

    # Check for the DLL in each subdirectory.
    for (
      dh = FindFirstFile(pattern:dir + subdir + "*");
      !isnull(dh);
      dh = FindNextFile(handle:dh)
    )
    {
      # Skip non-directories.
      if (dh[2] & FILE_ATTRIBUTE_DIRECTORY == 0)
        continue;

      # Skip current and parent directories.
      if (dh[1] == "." || dh[1] == "..")
        continue;

      # Skip anything that doesn't look like the 2010 branch.
      if (dh[1] !~ "^10\.")
        continue;

      # Get the version number from the file, if it exists.
      path = dir + subdir + dh[1] + "\" + file;
      fh = CreateFile(
        file               : path,
        desired_access     : GENERIC_READ,
        file_attributes    : FILE_ATTRIBUTE_NORMAL,
        share_mode         : FILE_SHARE_READ,
        create_disposition : OPEN_EXISTING
      );
      if (isnull(fh))
        continue;

      ver = GetFileVersion(handle:fh);
      CloseFile(handle:fh);

      check_vuln(
        name : appname,
        kb   : "2719584",
        path : windir + subdir + dh[1] + file,
        ver  : join(ver, sep:"."),
        fix  : "10.0.40219.417"
      );
    }

    # Clean up.
    NetUseDel(close:FALSE);
  }
  # no need to continue if vuln install found
  if (vuln) break;
}

hotfix_check_fversion_end();

if (!vuln) exit(0, "The host is not affected.");

# Flag the system as vulnerable.
set_kb_item(name:"SMB/Missing/" + bulletin, value:TRUE);
set_kb_item(name:"www/0/XSS", value:TRUE);
hotfix_security_warning();
