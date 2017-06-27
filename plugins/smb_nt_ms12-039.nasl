#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59457);
  script_version("$Revision: 1.28 $");
  script_cvs_date("$Date: 2016/12/09 21:04:54 $");

  script_cve_id("CVE-2011-3402", "CVE-2012-0159", "CVE-2012-1849", "CVE-2012-1858");
  script_bugtraq_id(50462, 53335, 53831, 53842);
  script_osvdb_id(73380, 76843, 81720, 82852, 82861);
  script_xref(name:"EDB-ID", value:"19777");
  script_xref(name:"MSFT", value:"MS12-039");

  script_name(english:"MS12-039: Vulnerabilities in Lync Could Allow Remote Code Execution (2707956)");
  script_summary(english:"Checks version of multiple files");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Lync.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is potentially affected by the following
vulnerabilities :

  - Multiple code execution vulnerabilities exist in the
    handling of specially crafted TrueType font files.
    (CVE-2011-3402, CVE-2012-0159)

  - An insecure library loading vulnerability exists in the
    way that Microsoft Lync handles the loading of DLL
    files. (CVE-2012-1849)

  - An HTML sanitization vulnerability exists in the way
    that HTML is filtered. (CVE-2012-1858)");
  # http://blog.watchfire.com/wfblog/2012/07/tostatichtml-the-second-encounter-cve-2012-1858-html-sanitizing-information-disclosure-introduction-t.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7d49512");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-129");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Aug/58");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-039");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Lync 2010, Lync 2010
Attendee, Lync 2010 Attendant, and Communicator 2007 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_communicator");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

global_var bulletin;

function get_user_dirs()
{
  local_var appdir, dirpat, domain, hklm, iter, lcpath, login, pass;
  local_var path, paths, pdir, port, rc, root, share, user, ver;

  paths = make_list();

  registry_init();
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
  pdir = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\ProfilesDirectory");
  if (pdir && stridx(tolower(pdir), "%systemdrive%") == 0)
  {
    root = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot");
    if (!isnull(root))
    {
      share = ereg_replace(string:root, pattern:"^([A-Za-z]):.*", replace:"\1:");
      pdir = share + substr(pdir, strlen("%systemdrive%"));
    }
  }
  RegCloseKey(handle:hklm);
  close_registry(close:FALSE);

  if (!pdir)
    return NULL;

  ver = get_kb_item("SMB/WindowsVersion");

  share = ereg_replace(string:pdir, pattern:"^([A-Za-z]):.*", replace:"\1$");
  dirpat = ereg_replace(string:pdir, pattern:"^[A-Za-z]:(.*)", replace:"\1\*");

  port    =  kb_smb_transport();
  if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
  login   =  kb_smb_login();
  pass    =  kb_smb_password();
  domain  =  kb_smb_domain();

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel(close:FALSE);
    return NULL;
  }

  # 2000 / XP / 2003
  if (ver < 6)
    appdir += "\Local Settings\Application Data";
  # Vista / 7 / 2008
  else
    appdir += "\AppData\Local";

  paths = make_array();
  iter = FindFirstFile(pattern:dirpat);
  while (!isnull(iter[1]))
  {
    user = iter[1];
    iter = FindNextFile(handle:iter);

    if (user == "." || user == "..")
      continue;

    path = pdir + "\" + user + appdir;

    lcpath = tolower(path);
    if (isnull(paths[lcpath]))
      paths[lcpath] = path;
  }

  NetUseDel(close:FALSE);

  return paths;
}

function check_vuln(file, fix, kb, key, min, paths)
{
  local_var base, hklm, path, result, rc, share;

  if (!isnull(key))
  {
    registry_init();
    hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
    base = get_registry_value(handle:hklm, item:key);
    RegCloseKey(handle:hklm);
    close_registry(close:FALSE);

    if (isnull(base))
      return FALSE;
  }

  if (isnull(paths))
    paths = make_list("");

  result = FALSE;
  foreach path (paths)
  {
    path = base + path;

    share = ereg_replace(string:path, pattern:"^([A-Za-z]):.*", replace:"\1$");
    if (!is_accessible_share(share:share))
      continue;

    rc = hotfix_check_fversion(file:file, version:fix, min_version:min, path:path, bulletin:bulletin, kb:kb);

    if (rc == HCF_OLDER)
      result = TRUE;
  }

  return result;
}

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS12-039";
kbs = make_list("2693282", "2693283", "2696031", "2702444", "2708980");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

# Add an extra node to the registry key if needed.
arch = get_kb_item_or_exit("SMB/ARCH", exit_code:1);
if (arch == "x64")
  extra = "\Wow6432Node";

######################################################################
# Microsoft Communicator 2007 R2
######################################################################
vuln = check_vuln(
  key  : "SOFTWARE\Microsoft\Communicator\InstallationDirectory",
  file : "Communicator.exe",
  min  : "3.5.0.0",
  fix  : "3.5.6907.253",
  kb   : "2708980"
);

######################################################################
# Microsoft Lync 2010
######################################################################
if (!vuln)
{
  vuln = check_vuln(
    key  : "SOFTWARE" + extra + "\Microsoft\Communicator\InstallationDirectory",
    file : "Communicator.exe",
    min  : "4.0.0.0",
    fix  : "4.0.7577.4098",
    kb   : "2693282"
  );
}

######################################################################
# Microsoft Lync 2010 Attendant
######################################################################
vuln = check_vuln(
  key  : "SOFTWARE" + extra + "\Microsoft\Attendant\InstallationDirectory",
  file : "AttendantConsole.exe",
  min  : "4.0.0.0",
  fix  : "4.0.7577.4098",
  kb   : "2702444"
) || vuln;

######################################################################
# Microsoft Lync 2010 Attendee (admin-level install)
######################################################################
vuln = check_vuln(
  key  : "SOFTWARE\Microsoft\AttendeeCommunicator\InstallationDirectory",
  file : "CURes.dll",
  min  : "4.0.0.0",
  fix  : "4.0.7577.4098",
  kb   : "2696031"
) || vuln;

######################################################################
# Microsoft Lync 2010 Attendee (user-level install)
######################################################################
paths = get_user_dirs();

if (!isnull(paths))
{
  vuln = check_vuln(
    paths : paths,
    file  : "\Microsoft Lync Attendee\System.dll",
    min   : "4.0.0.0",
    fix   : "4.0.60831.0",
    kb    : "2693283"
  ) || vuln;
}

# Disconnect from registry.
close_registry();

if (vuln)
{
  set_kb_item(name:"www/0/XSS", value:TRUE);

  set_kb_item(name:"SMB/Missing/" + bulletin, value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end();
  exit(0);
}

hotfix_check_fversion_end();
exit(0, "The host is not affected.");
