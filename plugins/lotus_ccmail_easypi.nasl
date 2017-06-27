#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100383);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/05/24 17:47:09 $");

  script_osvdb_id(155617);

  script_name(english:"Lotus CC:Mail Installed (EASYPI)");
  script_summary(english:"Checks the registry / file system for Lotus CC:Mail.");

  script_set_attribute(attribute:"synopsis", value:
"A vulnerable mail application is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"Lotus CC:Mail, an unsupported and vulnerable mail application, is
installed on the remote host. It is, therefore, affected by a
vulnerability that allows an unauthenticated, remote attacker to
execute arbitrary code.

EASYPI is one of multiple Equation Group vulnerabilities and exploits
disclosed on 2017/04/14 by a group known as the Shadow Brokers.");
  # https://github.com/misterch0c/shadowbroker/blob/bc8ff5f44a1a4a0431745467ba99f7aa6d723171/windows/exploits/Easypi-3.1.0.0.fb
  script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?0c829c90");
  # https://github.com/misterch0c/shadowbroker/blob/bc8ff5f44a1a4a0431745467ba99f7aa6d723171/windows/exploits/Easypi-3.1.0.0.xml
  script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?b45a28ea");
  # https://github.com/misterch0c/shadowbroker/blob/bc8ff5f44a1a4a0431745467ba99f7aa6d723171/windows/exploits/Easypi-3.1.0.exe
  script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?a19f2e5f");
  script_set_attribute(attribute:"solution", value:
"Lotus CC:Mail is no longer supported by the vendor. Upgrade to a
modern, up-to-date mail application that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

winver = get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);
if(ver_compare(ver:winver, fix:"6.0", strict:FALSE) >= 0) audit(AUDIT_OS_NOT, "Windows NT / 2000 / XP / 2003");

appname = "Lotus cc:Mail";
list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");

installed = FALSE;
version = NULL;

if (!isnull(list))
{
  foreach name (keys(list))
  {
    prod = list[name];
    if (!isnull(prod) && "cc:Mail" >< prod)
    {
      installed = TRUE;
      key = name;
      break;
    }
  }
}

if (!installed)
  audit(AUDIT_NOT_INST, appname);

registry_init();

key = key - "/DisplayName";
key = key - "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/";
key = "SOFTWARE\Lotus\" + key + "\Install\SMTPDirectory";

hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
path = get_registry_value(handle:hklm, item:key);

if (empty_or_null(path))
{
  RegCloseKey(handle:hklm);
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}

RegCloseKey(handle:hklm);
close_registry(close:FALSE);

exe = hotfix_append_path(path:path, value:"WINSMTP.exe");
version = hotfix_get_fversion(path:exe);
hotfix_handle_error(error_code:version['error'], file:exe, appname:appname, exit_on_fail:TRUE);
version = join(version['value'], sep:'.');

hotfix_check_fversion_end();

if (version)
{
  port = kb_smb_transport();
  report = '\n  Path    : ' + exe +
           '\n  Version : ' + version + '\n';

  security_report_v4(severity:SECURITY_HOLE, extra:report, port:port);
}
else audit(AUDIT_NOT_INST, appname);
