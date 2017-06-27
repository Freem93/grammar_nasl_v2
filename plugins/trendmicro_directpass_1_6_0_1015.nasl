#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(66811);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/02/13 21:07:14 $");

  script_bugtraq_id(60023);
  script_osvdb_id(93549, 93550, 93551);
  script_xref(name:"EDB-ID", value:"25719");

  script_name(english:"Trend Micro DirectPass < 1.6.0.1015 Multiple Vulnerabilities");
  script_summary(english:"Checks Trend Micro DirectPass version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a program that is potentially affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Trend Micro DirectPass on the remote Windows host is
earlier than 1.6.0.1015 and is, therefore, potentially affected by the
following vulnerabilities :

  - An input validation error exists in the file
    'InstallWorkspace.exe' related to the 'Master Password'
    field that could allow persistent cross-site scripting
    attacks.

  - An error exists in the file 'InstallWorkspace.exe'
    related to the 'Master Password' module that could
    allow a security bypass and arbitrary command execution.

  - An error exists in the files 'InstallWorkspace.exe' and
    'libcef.dll' that could allow denial of service attacks
    because of dereferencing a NULL pointer.");

  script_set_attribute(attribute:"see_also", value:"http://esupport.trendmicro.com/solution/en-US/1096805.aspx");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2013/May/112");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.6.0.1015.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:trend_micro:directpass");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated');

appname = "Trend Micro DirectPass";
registry_init();
handle = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\TrendMicro\TMIDS";
item = get_values_from_key(handle:handle, key:key, entries:make_list("ProductPath"));
if (!isnull(item)) path = item['ProductPath'];
else
{
  list = get_kb_list_or_exit("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
  foreach name (keys(list))
  {
    prod = list[name];
    if (appname >< prod)
    {
      installstring = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/.+)\/DisplayName$", replace:"\1", string:name);
      key = str_replace(find:"/", replace:"\", string:installstring);
      item = get_values_from_key(handle:handle, key:key, entries:make_list("InstallLocation"));
      path = item['InstallLocation'];
      if (strlen(path) > 1) break;
    }
  }
}
RegCloseKey(handle:handle);
if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
close_registry(close:FALSE);

file_path = path + "InstallWorkspace.exe";
ver = hotfix_get_fversion(path:file_path);
hotfix_check_fversion_end();

if (ver['error'] == HCF_NOENT) audit(AUDIT_UNINST, appname);
else if (ver['error'] != HCF_OK) audit(AUDIT_VER_FAIL, file_path);

version = join(ver['value'], sep:".");

fixed_version = "1.6.0.1015";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  port = kb_smb_transport();
  set_kb_item(name:"www/0/XSS", value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + file_path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);
