#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59243);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/04 18:02:14 $");

  script_bugtraq_id(53438);
  script_osvdb_id(81785);
  script_xref(name:"Secunia", value:"49050");

  script_name(english:"Core FTP Filename Processing Boundary Error FTP List Command Response Parsing Remote Overflow");
  script_summary(english:"Checks version of Core FTP");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An FTP client on the remote host is affected by a buffer overflow
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Core FTP installed on the remote host is less than 2.2
build 1745.  It thus is reportedly affected by a buffer overflow
vulnerability that can be triggered when it receives a specially
crafted FTP LIST command response.

By tricking a user into connecting to a malicious server, a remote
attacker may be able to execute arbitrary code on the affected host,
subject to the user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"http://coreftp.com/forums/viewtopic.php?t=137481");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Core FTP 2.2 build 1745 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:coreftp:coreftp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("audit.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

appname = 'Core FTP';
port = get_kb_item("SMB/transport");

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\FTPWare\CoreFTP\Install_Dir";
path = get_registry_value(handle:hklm, item:key);
if (isnull(path))
{
  list = get_kb_list_or_exit("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
  foreach name (keys(list))
  {
    prod = list[name];
    if ("Core FTP" >< prod)
    {
      installstring = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/.+)\/DisplayName$", replace:"\1", string:name);
      uninstall_key = str_replace(find:"/", replace:"\", string:installstring);
      value = get_values_from_key(handle:hklm, key:uninstall_key, entries:make_list('UninstallString'));
      if (isnull(value)) continue;

      uninstall_string = value['UninstallString'];
      if (isnull(uninstall_string)) continue;

      uninstall_string = eregmatch(string:uninstall_string, pattern:"([A-Za-z]:\\.*\\)[^\\]+\.exe",icase:TRUE);
      if (!isnull(uninstall_string))
      {
        path = uninstall_string[1];
        break;
      }
    }
  }
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
close_registry(close:FALSE);

exe = path + "\coreftp.exe";

ver = hotfix_get_fversion(path:exe);
hotfix_check_fversion_end();

if (ver['error'] != HCF_OK)
{
  # file does not exist, so application must have been
  # uninstalled uncleanly
  if (ver['error'] == HCF_NOENT) audit(AUDIT_UNINST, appname);

  # other error
  exit(1, "Error obtaining version of '" + exe + "'");
}

version = join(sep:'.', ver['value']);

kb_base = "SMB/CoreFTP/";
set_kb_item(name:kb_base + "Installed", value:TRUE);
set_kb_item(name:kb_base + "Version", value:version);
set_kb_item(name:kb_base + "Path", value:path);

fix = "2.2.1745.0";
if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report = '\n  Path              : ' + path +
             '\n  Installed version : ' + version +
             '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:port,extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);
