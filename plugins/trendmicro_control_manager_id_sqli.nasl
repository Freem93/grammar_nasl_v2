#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62628);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2012/12/28 21:13:29 $");

  script_cve_id("CVE-2012-2998");
  script_bugtraq_id(55706);
  script_osvdb_id(85807);
  script_xref(name:"CERT", value:"950795");
  script_xref(name:"EDB-ID", value:"21546");

  script_name(english:"Trend Micro Control Manager AdHocQuery_Processor.aspx id Parameter SQL Injection");
  script_summary(english:"Checks version of AdHocQuery.NET.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a web application that is affected by a SQL
injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"Trend Micro Control Manager, a centralized threat and data protection
management application, is installed on the remote Windows host and is
potentially affected by a SQL injection vulnerability because the
application fails to properly sanitize user-supplied input to the 'id'
parameter of the AdHocQuery_Processor.aspx script. 

By exploiting this flaw, a remote, authenticated attacker, could launch
a SQL injection attack against the affected application, leading to the
discovery of sensitive information, attacks against the underlying
database, and the like.");
  # http://www.spentera.com/2012/09/trend-micro-control-manager-sql-injection-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e442f79");
  script_set_attribute(attribute:"see_also", value:"http://esupport.trendmicro.com/solution/en-us/1061043.aspx");
  script_set_attribute(attribute:"solution", value:
"Critical Patch - Build 1823 is available for Trend Micro Control
Manager 5.5.  Critical Patch - Build 1449 is available for Trend Micro
Control Manager 6.0.  If you are using an older version, upgrade to
either 5.5 or 6.0 and apply the relevant patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:trend_micro:control_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

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

port = kb_smb_transport();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\TrendMicro\TVCS";
path = get_registry_value(handle:hklm, item:key + "\HomeDirectory");

if (isnull(path))
{
  RegCloseKey(handle:hklm);
  close_registry();
  audit(AUDIT_NOT_INST, 'Trend Micro Control Manager');
}
appver = get_registry_value(handle:hklm, item:key + "\Version");
RegCloseKey(handle:hklm);

if (isnull(appver))
{
  close_registry();
  exit(1, 'Failed to determine the version of Trend Micro Control Manager from the registry.');
}
close_registry(close:FALSE);

# For versions before 6.0, try to get the version from the COMMON directory
if (appver =~ '^[0-5]\\.[05]$')
{
  dll = path - 'Control Manager';
  dll += "COMMON\ccgi\WebUI\WebApp\Bin\AdHocQuery.NET.dll";
  ver = hotfix_get_fversion(path:dll);
  if (ver['error'] != HCF_NOENT && ver['error'] != HCF_OK)
  {
    hotfix_check_fversion_end();
    audit(AUDIT_VER_FAIL, dll);
  }

  # If the file didn't exist, check the Control Manager dir
  if (ver['error'] == HCF_NOENT)
  {
    dll = path + "\WebUI\WebApp\Bin\AdHocQuery.NET.dll";
    ver = hotfix_get_fversion(path:dll);
    hotfix_check_fversion_end();

    if (ver['error'] == HCF_NOENT)
      audit(AUDIT_UNINST, 'Trend Micro Control Manager');
    else if (ver['error'] != HCF_OK)
      audit(AUDIT_VER_FAIL, dll);
  }
  version = join(sep:'.', ver['value']);
}

else if (appver =~ '^6\\.0$')
{
  dll = path + "\WebUI\WebApp\Bin\AdHocQuery.NET.dll";
  ver = hotfix_get_fversion(path:dll);
  hotfix_check_fversion_end();

  if (ver['error'] == HCF_NOENT)
    audit(AUDIT_UNINST, 'Trend Micro Control Manager');
  else if (ver['error'] != HCF_OK)
    audit(AUDIT_VER_FAIL, dll);
  version = join(sep:'.', ver['value']);
}

if (((version =~ '^3\\.[05]\\.' || version =~ '^5\\.[05]\\.') && ver_compare(ver:version, fix:'5.5.0.1793') == -1))
  fixed_version = '5.5.0.1793';
else if (version =~ '^6\\.0\\.' && ver_compare(ver:version, fix:'6.0.0.1449') == -1)
  fixed_version = '6.0.0.1449';

if (fixed_version)
{ 
  set_kb_item(name:'www/0/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Product version       : ' + appver +
      '\n  DLL                   : ' + dll +
      '\n  Installed DLL version : ' + version +
      '\n  Fixed DLL version     : ' + fixed_version + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, 'AdHocQuery.NET.dll located under ' + (dll - 'AdHocQuery.NET.dll') + ' is version ' + version + ' and thus is not affected.');
