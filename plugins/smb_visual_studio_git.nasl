#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80333);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/06 17:22:01 $");

  script_cve_id("CVE-2014-9390");
  script_bugtraq_id(71732);
  script_osvdb_id(116041);

  script_name(english:"Microsoft Visual Studio .git\config Command Execution");
  script_summary(english:"Checks file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by a
command execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Visual Studio installed on the remote host is affected
by a command execution vulnerability when processing specially crafted
git trees in a case-insensitive or case-normalizing file system. A
remote attacker, using a specially crafted git tree, can overwrite a
user's '.git/config' file when the user clones or checks out a
repository, allowing arbitrary command execution.");
  # http://blogs.msdn.com/b/bharry/archive/2014/12/18/git-vulnerability-with-git-config.aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d6c4ffe");
  script_set_attribute(attribute:"see_also", value:"http://article.gmane.org/gmane.linux.kernel/1853266");
  # http://git-blame.blogspot.com/2014/12/git-1856-195-205-214-and-221-and.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?afc47628");
  script_set_attribute(attribute:"solution", value:"Apply the appropriate patches as recommended by Microsoft.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Malicious Git and Mercurial HTTP Server For CVE-2014-9390');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:microsoft:visual_studio_team_foundation_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:git:git");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "microsoft_team_foundation_server_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

include('audit.inc');
include("smb_hotfixes.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");

registry_init();

hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

vs_2013_install_path_key = "SOFTWARE\Microsoft\VisualStudio\12.0\Setup\VS\ProductDir";
vs_2012_install_path_key = "SOFTWARE\Microsoft\VisualStudio\11.0\Setup\VS\ProductDir";

vs_2012_install_path = get_registry_value(handle:hklm, item:vs_2012_install_path_key);
vs_2013_install_path = get_registry_value(handle:hklm, item:vs_2013_install_path_key);
num_tfs_installs = get_kb_item("SMB/Microsoft_Team_Foundation_Server/NumInstalled");

RegCloseKey(handle:hklm);

tfs_2013_found = FALSE;
if(!isnull(num_tfs_installs))
  for(i=0; i<num_tfs_installs; i++)
    if(get_kb_item("SMB/Microsoft_Team_Foundation_Server/" + i + "/Version") =~ "^12\.")
      tfs_2013_found = TRUE;

if(isnull(vs_2012_install_path) && isnull(vs_2013_install_path) && !tfs_2013_found)
  audit(AUDIT_NOT_INST, "Microsoft Visual Studio 2012, 2013, or Team Foundation Server 2013");

vs_2012_vuln_users_info = '';
report = '';

if(!isnull(vs_2012_install_path))
{
  # check each user
  hku = registry_hive_connect(hive:HKEY_USERS, exit_on_fail:TRUE);
  subkeys = get_registry_subkeys(handle:hku, key:'');

  foreach key (subkeys)
  {
    if ('.DEFAULT' >< key || 'Classes' >< key ||
       key =~ "^S-1-5-\d{2}$") # skip built-in accounts
      continue;

    extensions = get_reg_name_value_table(handle:hku ,key:key + "\Software\Microsoft\VisualStudio\11.0\ExtensionManager\EnabledExtensions");

    foreach ext (keys(extensions))
    {
      if('microsoft.teamfoundation.git.provider' >< ext)
      {
        git_tools_path = extensions[ext];

        if(hotfix_check_fversion(file: "git2-msvstfs.dll",
                                 version: "0.20.2",
                                 min_version: "0.20",
                                 path:git_tools_path) == HCF_OLDER)
        {
          vs_2012_vuln_users_info += '\n   User SID : ' + key +
                                     '\n     Extension path : ' + git_tools_path + 
                                     '\n     Unpatched DLL  : git2-msvstfs.dll\n';
        }
      }
    }
  }
}

RegCloseKey(handle:hku);

# add to report if vulnerable extensions found
if(vs_2012_vuln_users_info != '')
{
  report += '\nThe following users have unpatched Visual Studio 2012 Git Tools\nExtensions : \n' +
            vs_2012_vuln_users_info;
}

# check VS 2013 Team Foundation Server
if(tfs_2013_found)
{
  tfs_2013_info = '';
  for(i=0; i<num_tfs_installs; i++)
  {
    tfs_ver = get_kb_item("SMB/Microsoft_Team_Foundation_Server/" + i + "/Version");
    if(tfs_ver !~ "^12\.0") continue;

    tfs_2013_install_path = get_kb_item("SMB/Microsoft_Team_Foundation_Server/" + i + "/Path");
    # should never happen, but check just in case
    if(isnull(tfs_2013_install_path)) continue;

    ret = hotfix_get_fversion(path:hotfix_append_path(path:tfs_2013_install_path, value:"Application Tier\Web Services\bin\Microsoft.TeamFoundation.Git.Server.dll"));
    if (ret['error'] != HCF_OK)
    {
      hotfix_check_fversion_end();
      audit(AUDIT_FN_FAIL, 'hotfix_get_fversion');
    }
    git_ver = join(ret['value'], sep:'.');

    if(git_ver =~ "^12\.0\.2\d{4}\." &&
       ver_compare(fix:"12.0.22416.3", ver:git_ver, strict:FALSE) == -1)
    {
      tfs_2013_info += '\n  Install Path  : ' + tfs_2013_install_path +
                       '\n  Unpatched DLL : Application Tier\\Web Services\\bin\\Microsoft.TeamFoundation.Git.Server.dll' +
                       '\n  DLL Version   : ' + git_ver +
                       '\n  Fixed Version : 12.0.22416.3' +
                       '\n  Required KB   : KB3023302\n';
    }
    else if(git_ver =~ "^12\.0\.3\d{4}\." &&
            ver_compare(fix:"12.0.31115.1", ver:git_ver, strict:FALSE) == -1)
    {
      tfs_2013_info += '\n  Install Path  : ' + tfs_2013_install_path +
                       '\n  Unpatched DLL : Application Tier\\Web Services\\bin\\Microsoft.TeamFoundation.Git.Server.dll' +
                       '\n  DLL Version   : ' + git_ver +
                       '\n  Fixed Version : 12.0.31115.1' +
                       '\n  Required KB   : KB3023304 (with SP4)\n';
    }
  }

  if(tfs_2013_info != '')
  {
    report += '\nThe following vulnerable Visual Studio Team Foundation Server 2013\nInstalls were found : \n' +
              tfs_2013_info;
  }
}

if(!isnull(vs_2013_install_path))
{
  vs_2013_info = '';

  ret = hotfix_get_fversion(path:hotfix_append_path(path:vs_2013_install_path, value:"Common7\IDE\CommonExtensions\Microsoft\TeamFoundation\Team Explorer\git2-msvstfs.dll"));

  if (ret['error'] != HCF_OK)
  {
    hotfix_check_fversion_end();
    audit(AUDIT_FN_FAIL, 'hotfix_get_fversion');
  }
  git_ver = join(ret['value'], sep:'.');

  if(ver_compare(fix:"0.20.2.0", ver:git_ver, strict:FALSE) == -1)
  {
    vs_2013_info = '\n  Install Path  : ' + vs_2013_install_path +
                   '\n  Unpatched DLL : Common7\\IDE\\CommonExtensions\\Microsoft\\TeamFoundation\\Team Explorer\\git2-msvstfs.dll' +
                   '\n  DLL version   : ' + git_ver +
                   '\n  Fixed version : 0.20.2.0' +
                   '\n  Required KB   : KB3023576\n';
  }
  else if(git_ver =~ "^0\.20\.\d{5}\." &&
          ver_compare(fix:"0.20.31212.0", ver:git_ver, strict:FALSE) == -1)
  {
    vs_2013_info = '\n  Install Path  : ' + vs_2013_install_path +
                   '\n  Unpatched DLL : Common7\\IDE\\CommonExtensions\\Microsoft\\TeamFoundation\\Team Explorer\\git2-msvstfs.dll' +
                   '\n  DLL version   : ' + git_ver +
                   '\n  Fixed version : 0.20.31212.0' +
                   '\n  Required KB   : KB3023577 (with SP4)\n';
  }

  if(vs_2013_info != '')
  {
    report += '\nThe following vulnerable Visual Studio 2013 install was found : \n' +
              vs_2013_info;
  }
}

hotfix_check_fversion_end();

if(report != '')
{
  port = kb_smb_transport();
  if(report_verbosity > 0)
    security_warning(port:port, extra:report);
  else security_warning(port:port);
}
else audit(AUDIT_HOST_NOT, 'affected');
