#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69555);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/12 17:12:45 $");

  script_name(english:"KINS Banking Trojan/Data Theft (credentialed check)");
  script_summary(english:"Looks for files indicative of the KINS Trojan");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host has been infected with the KINS Trojan.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has files that indicate that the KINS banking
Trojan has been installed.

False positives may occur if file names identical to files KINS
creates are detected on the system.");
  script_set_attribute(
    attribute:"see_also",
    value:"https://blogs.rsa.com/is-cybercrime-ready-to-crown-a-new-kins-inth3wild/"
  );
  script_set_attribute(attribute:"solution", value:
"Update the host's antivirus software, clean the host, and scan again
to ensure its removal. If symptoms persist, re-installation of the
infected host is recommended.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Backdoors");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion", "Settings/ParanoidReport");
  script_require_ports(139, 445);

  exit(0);
}


include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

##
# Get list of all user Directories
##
function get_user_dirs(login, pass, domain)
{
  local_var appdir, dirpat, hklm, iter, lcpath;
  local_var path, paths, pdir, rc, root, share, user, ver;

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:'IPC$');
  if ( rc != 1 )
  {
    NetUseDel(close:FALSE);
    audit(AUDIT_SHARE_FAIL, 'IPC$');
  }
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
  pdir = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\ProfilesDirectory");
  if (pdir && stridx(tolower(pdir), "%systemdrive%") == 0)
  {
    root = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot");
    if (!isnull(root))
    {
      share = hotfix_path2share(path:root);
      pdir = share - '$' + ':' + substr(pdir, strlen("%systemdrive%"));
    }
  }
  RegCloseKey(handle:hklm);
  NetUseDel(close:FALSE);

  if (!pdir)
    return NULL;

  ver = get_kb_item_or_exit("SMB/WindowsVersion");

  share = hotfix_path2share(path:pdir);
  dirpat = ereg_replace(string:pdir, pattern:"^[A-Za-z]:(.*)", replace:"\1\*");

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel(close:FALSE);
    audit(AUDIT_SHARE_FAIL, share);
  }

  # 2000 / XP / 2003
  if (ver < 6)
    appdir += "\Application Data";
  # Vista / 7 / 2008
  else
    appdir += "\AppData\Roaming";

  paths = make_array();
  iter = FindFirstFile(pattern:dirpat);
  while (!isnull(iter[1]))
  {
    user = iter[1];
    iter = FindNextFile(handle:iter);

    if (user == "." || user == "..")
      continue;

    path = pdir + '\\' + user + appdir;

    paths[tolower(user)] = path;
  }

  NetUseDel(close:FALSE);

  return paths;
}

##
# Check for KINS
##
function check_kins(pdir)
{
  local_var iter, iter2, dir, file, kins_files, kins_dirs;
  local_var tmp_dir, exe_dir, dll_dir, bad_dir;

  kins_dirs = make_array();
  kins_dirs["exe"] = make_array();
  kins_dirs["tmp"] = make_array();

  # Search for KINS directories.
  iter = FindFirstFile(pattern:pdir + "\*");
  while (!isnull(iter[1]))
  {
    dir = iter[1];
    iter = FindNextFile(handle:iter);

    if (dir == "." || dir == "..")
      continue;

    # KINS creates two directories.
    # Starting with capitol letter followed by 3 to 5 lowercase letters.
    if (eregmatch(pattern:"^[A-Z][a-z]{3,5}$", string:dir))
    {
      tmp_dir = FALSE;
      exe_dir = FALSE;
      dll_dir = FALSE;
      bad_dir = FALSE;
      kins_files = make_list();
      iter2 = FindFirstFile(pattern:pdir + '\\' + dir + "\*");
      while (!isnull(iter2[1]))
      {
        file = iter2[1];
        iter2 = FindNextFile(handle:iter2);

        if (file == "." || file == "..")
          continue;

        # One of the directories contains a .exe with a name all
        # lowercase letters 4 to 5 letters long.
        if (!exe_dir && eregmatch(pattern:"^[a-z]{4,5}\.exe$", string:file))
        {
          exe_dir = TRUE;
          kins_files[max_index(kins_files)] = file;
        }
        # One of the directories contains a .tmp with a name all
        # lowercase letters 4 to 5 letters long.
        else if (!tmp_dir && eregmatch(pattern:"^[a-z]{4,5}\.tmp$", string:file))
        {
          tmp_dir = TRUE;
          kins_files[max_index(kins_files)] = file;
        }
        # The directory with the exe could contain dll(s) with
        # a name 3 characters long.
        else if(eregmatch(pattern:"^.{3}\.dll$", string:file))
        {
          dll_dir = TRUE;
          kins_files[max_index(kins_files)] = file;
        }
        # If the directory contains anything but a single exe with N dll(s)
        # or a single tmp file it is thrown out.
        else
        {
          bad_dir = TRUE;
          break;
        }
      }

      # Make sure is a KINS directory.
      if (!bad_dir)
      {
        # Valid exe directory
        if (exe_dir && !tmp_dir)
        {
          kins_dirs["exe"][dir] = kins_files;
        }
        # Valid tmp directory
        else if (tmp_dir && !exe_dir && !dll_dir)
        {
          kins_dirs["tmp"][dir] = kins_files;
        }
      }
    }
  }

  # There must be at least one valid exe directory and one valid tmp directory
  # Allow for more just in case of reinfection.
  if (max_index(keys(kins_dirs["exe"])) > 0 && max_index(keys(kins_dirs["tmp"])) > 0)
  {
    return kins_dirs;
  }
  else
  {
    return NULL;
  }
}

if (report_paranoia < 2) audit(AUDIT_PARANOID);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion");

name    =  kb_smb_name();
port    =  kb_smb_transport();

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

# Retrieve users directories. KINS stores its files in the users profile.
user_dirs = get_user_dirs(login: login, pass: pass, domain: domain);
if (isnull(user_dirs))
{
  NetUseDel();
  exit(1, "Couldn't retrieve list of user's profiles.");
}

infected_users = make_array();

share = "";
tmp_share = "";
foreach user (keys(user_dirs))
{
  # Make sure we are connected to share containing the profile
  # Only (re)connect if share changes.
  tmp_share = toupper(ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:user_dirs[user]));
  if (tmp_share != share)
  {
    if (share != "")
    {
      NetUseDel(close: FALSE);
    }

    share = tmp_share;

    rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
    if (rc != 1)
    {
      NetUseDel();
      audit(AUDIT_SHARE_FAIL, share);
    }
  }

  pdir = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:user_dirs[user]);
  res = check_kins(pdir: pdir);
  if (!isnull(res))
  {
    infected_users[user] = res;
  }
}

NetUseDel();

# Check if any of the users have indicators of infection.
if (max_index(keys(infected_users)) > 0)
{
  if (report_verbosity > 0)
  {
    report = 'The following users show signs of being infected by the KINS trojan : \n\n';
    foreach user (keys(infected_users))
    {
      report += user + ' : \n';
      foreach type (make_list("exe", "tmp"))
      {
        foreach dir (keys(infected_users[user][type]))
        {
          foreach file (infected_users[user][type][dir])
          {
            report += '  ' + user_dirs[user] + '\\' + dir + '\\' + file + '\n';
          }
        }
      }
      report += '\n';
    }
    security_hole(port:port, extra:report);
  }
  else
  {
    security_hole(port);
  }
}
else
{
  exit(0, "The KINS trojan was not found.");
}
