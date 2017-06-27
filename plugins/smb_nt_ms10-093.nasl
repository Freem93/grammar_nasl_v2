#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51165);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2017/05/10 13:37:30 $");

  script_cve_id("CVE-2010-3967");
  script_bugtraq_id(42659);
  script_osvdb_id(67543);
  script_xref(name:"MSFT", value:"MS10-093");
  script_xref(name:"EDB-ID", value:"14731");

  script_name(english:"MS10-093: Vulnerability in Windows Movie Maker Could Allow Remote Code Execution (2424434)");
  script_summary(english:"Checks version of Moviemk.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by a flaw in Windows Movie Maker due to a failure
to correctly restrict the path being used for loading external
libraries. An unauthenticated, remote attacker can exploit this to
execute arbitrary code with the user's privileges by convincing the
user to open a specially crafted Windows Movie Maker (.mswmm) file
that is located in the same network directory as a specially crafted
dynamic link library (DLL) file.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-093");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:windows_movie_maker");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS10-093';
kbs = make_list("2424434");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'1,2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

arch = get_kb_item_or_exit("SMB/ARCH", exit_code:1);

# Figure out where Movie Maker 2.6's installed.
paths = make_array();

progfiles = hotfix_get_programfilesdir();

port    = kb_smb_transport();
login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

hcf_init = TRUE;

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

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\moviemk.exe";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(item) && strlen(item[1]) > 0 )
  {
    path = item[1];
    path = ereg_replace(
      pattern:"^(.+)\\moviemk\.exe$",
      replace:"\1",
      string:path,
      icase:TRUE
    );
    path = ereg_replace(
      pattern:"%ProgramFiles%",
      replace:progfiles,
      string:path,
      icase:TRUE
    );
    paths[tolower(path)]++;
  }
  RegCloseKey(handle:key_h);
}

key = "SOFTWARE\Classes\Windows.Movie.Maker\Shell\Open\Command";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(item) && strlen(item[1]) > 0 )
  {
    path = item[1];
    path = ereg_replace(pattern:'^"([^"]+)".*', replace:"\1", string:path);
    if (preg(pattern:"moviemk\.exe([.\s]+)?", string:path, icase:TRUE))
    {
      path = ereg_replace(pattern:"^(.+)\\\moviemk\.exe(.+)?$", replace:"\1", string:path);
      path = ereg_replace(
        pattern:"%ProgramFiles%",
        replace:hotfix_get_programfilesdir(),
        string:path,
        icase:TRUE
      );
      paths[tolower(path)]++;
    }
    RegCloseKey(handle:key_h);
  }
}

path = hotfix_get_programfilesdir() + "\Movie Maker 2.6";
paths[tolower(path)]++;

if (arch == "x64")
{
  key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths\moviemk.exe";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(item) && strlen(item[1]) > 0 )
    {
      path = item[1];
      path = ereg_replace(
        pattern:"^(.+)\\moviemk\.exe$",
        replace:"\1",
        string:path,
        icase:TRUE
      );
      path = ereg_replace(
        pattern:"%ProgramFiles%",
        replace:progfiles,
        string:path,
        icase:TRUE
      );
      paths[tolower(path)]++;
    }
    RegCloseKey(handle:key_h);
  }

  key = "SOFTWARE\Wow6432Node\Classes\Windows.Movie.Maker\Shell\Open\Command";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(item) && strlen(item[1]) > 0 )
    {
      path = item[1];
      path = ereg_replace(pattern:'^"([^"]+)".*', replace:"\1", string:path);
      if (preg(pattern:"moviemk\.exe([.\s]+)?", string:path, icase:TRUE))
      {
        path = ereg_replace(pattern:"^(.+)\\\moviemk\.exe(.+)?$", replace:"\1", string:path);
        path = ereg_replace(
          pattern:"%ProgramFiles%",
          replace:hotfix_get_programfilesdir(),
          string:path,
          icase:TRUE
        );
        paths[tolower(path)]++;
      }
      RegCloseKey(handle:key_h);
    }
  }

  path = hotfix_get_programfilesdirx86() + "\Movie Maker 2.6";
  paths[tolower(path)]++;
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

# Loop through each searching for an affected install.
#
# nb: I don't know if this can be installed more than once so we'll stop after the first install.

kb = "2424434";
foreach path (keys(paths))
{

  share = hotfix_path2share(path:path);
  if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

  if (
    # Vista
    hotfix_is_vulnerable(os:"6.0", file:"Moviemk.exe", version:"2.6.4040.0", min_version:"2.6.0.0", path:path, bulletin:bulletin, kb:kb)
  )
  {
    set_kb_item(name:"SMB/Missing/MS10-093", value:TRUE);
    hotfix_security_hole();

    hotfix_check_fversion_end();
    exit(0);
  }
}

hotfix_check_fversion_end();
audit(AUDIT_HOST_NOT, 'affected');
