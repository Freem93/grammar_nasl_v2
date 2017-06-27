#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(72880);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/03/14 19:51:45 $");

  script_cve_id("CVE-2014-0890");
  script_bugtraq_id(65937);
  script_osvdb_id(104046);

  script_name(english:"IBM Lotus Sametime Connect Audio / Video Chat Information Disclosure");
  script_summary(english:"Checks version of IBM Lotus Sametime Connect Client");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has a chat client that is affected by an
information disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of IBM Lotus Sametime Connect installed on the remote
Windows host is potentially affected by an information disclosure
vulnerability.  If a user sets a certain log flag to high and uses
Audio/Video chat, the user's password is stored in plaintext
(unencrypted)."
  );
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21665658");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/ibm_security_bulletin_passwords_may_be_logged_when_some_high_logging_level_flag_is_used_cve_2014_0890?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8bb53e2c");
  # http://packetstormsecurity.com/files/125326/Lotus-Sametime-8.5.1-Password-Disclosure.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?62318ddd");
  script_set_attribute(attribute:"solution", value:"Apply the patch referenced in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:sametime");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("lotus_sametime_connect_installed.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/IBM Lotus Sametime Client/Path", "SMB/IBM Lotus Sametime Client/Version", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

app_name = "IBM Lotus Sametime Connect Client";
version = get_kb_item_or_exit('SMB/IBM Lotus Sametime Client/Version');
path    = get_kb_item_or_exit('SMB/IBM Lotus Sametime Client/Path');
fixpackdate = get_kb_item('SMB/IBM Lotus Sametime Client/fixpackdate');
winver = get_kb_item_or_exit("SMB/WindowsVersion");

# Looks for Sametime preference files with vulnerable log flags.
function check_sametime_logging(dir)
{
  local_var hklm, subkeys, profile_key, sid;
  local_var system_root;
  local_var vulnerable_files;
  vulnerable_files = make_list();

  registry_init();
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
  profile_key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
  subkeys = get_registry_subkeys(handle:hklm, key:profile_key);
  RegCloseKey(handle:hklm);
  system_root = hotfix_get_systemroot();
  if (isnull(system_root)) exit(1, "Unable to get system root directory.");
  if (!isnull(subkeys))
  {
    foreach sid (subkeys)
    {
      local_var appdata_path;
      registry_init();
      hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
      appdata_path = get_registry_value(handle:hklm, item:strcat(profile_key,"\",sid,"\ProfileImagePath"));
      RegCloseKey(handle:hklm);
      if (!isnull(appdata_path))
      {
        local_var sametime_log_path;
        sametime_log_path = hotfix_append_path(path:appdata_path, value:strcat(dir, "\.config\rcpinstall.properties"));
        sametime_log_path = str_replace(string:sametime_log_path, find:"%systemroot%", replace:system_root);

        if (hotfix_file_exists(path:sametime_log_path))
        {
          local_var contents;
          contents = hotfix_get_file_contents(sametime_log_path);

          if ( contents['error'] == HCF_OK &&
            ereg(string:contents['data'], pattern:"com\.ibm\.collaboration\.realtime\.telephony(\..*)?\.level=FINE", multiline:TRUE))
          {
            vulnerable_files = make_list(vulnerable_files, sametime_log_path);
          }
        }
      }
    }
  }
  RegCloseKey(handle:hklm);
  close_registry();

  return vulnerable_files;
}

# Add vulnerable files to report.
function report_high_logging(report, logs)
{
  local_var log;

  report += '\n  High level log flags were detected in the following files:';

  foreach log (logs)
  {
    report += '\n    - ' + log;
  }

  report += '\n';

  return report;
}

vuln = FALSE;
fixdate = NULL;
workspace_dir = NULL;
if (winver < 6) base_workspace = "\Application Data";
else base_workspace = "\AppData\Roaming";
# Only 8.5.1, 8.5.2 and 9.0.0 are affected.
if (version =~ "^8\.5\.1( .*)?$")
{
  # Check the fixpack timestamp
  if (isnull(fixpackdate)) vuln = TRUE;
  else
  {
    fixdate = "20140224";
    fixpackdate = ereg_replace(pattern:'^([0-9]+)-[0-9]+$', replace:"\1", string:fixpackdate);
    if (int(fixpackdate) < fixdate)  vuln = TRUE;
  }
  workspace_dir = hotfix_append_path(path:base_workspace, value:"\Lotus\Sametime");
}
else if (version =~ "^8\.5\.2( .*)?$")
{
  # Check the fixpack timestamp
  if (isnull(fixpackdate)) vuln = TRUE;
  else
  {
    fixdate = "20140225";
    fixpackdate = ereg_replace(pattern:'^([0-9]+)-[0-9]+$', replace:"\1", string:fixpackdate);
    if (int(fixpackdate) < fixdate)  vuln = TRUE;
  }
  workspace_dir = hotfix_append_path(path:base_workspace, value:"\Lotus\Sametime");
}
else if (version =~ "^9\.0\.0( .*)?$")
{
  # Check the fixpack timestamp
  if (isnull(fixpackdate)) vuln = TRUE;
  else
  {
    fixdate = "20140225";
    fixpackdate = ereg_replace(pattern:'^([0-9]+)-[0-9]+$', replace:"\1", string:fixpackdate);
    if (int(fixpackdate) < fixdate) vuln = TRUE;
  }
  workspace_dir = hotfix_append_path(path:base_workspace, value:"\IBM\Sametime");
}

# If doing a paranoid scan, then we're done. Otherwise, if not doing
# a paranoid scan and detected a vulnerable version, check logging
# levels per the advisory.
if (vuln && report_paranoia < 2)
{
  vuln = FALSE;
  logs = check_sametime_logging(dir:workspace_dir);
  if (max_index(logs) > 0) vuln = TRUE;
}

if (vuln)
{
  port = kb_smb_transport();

  if (report_verbosity > 0)
  {
    report =
      '\n  Path                    : ' + path +
      '\n  Installed version       : ' + version;

    if (!isnull(fixpackdate))
    {
      report +=
        '\n  Installed Fix Pack date : ' + fixpackdate +
        '\n  Fixed Fix Pack date     : ' + fixdate + '\n';
    }
    else report += '\n  No Fix Packs have been applied.\n';

    if (logs) report = report_high_logging(report:report, logs:logs);

    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
