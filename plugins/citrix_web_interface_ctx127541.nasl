#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67193);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/04 18:02:13 $");

  script_cve_id("CVE-2010-4515");
  script_bugtraq_id(45291);
  script_osvdb_id(69676);
  script_xref(name:"IAVB", value:"2010-B-0112");

  script_name(english:"Citrix Web Interface 5.x < 5.4 Unspecified XSS");
  script_summary(english:"Checks the Version of Citrix Web Interface");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web application that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a version of Citrix Web Interface 5.x earlier
than 5.4.0.  Such versions are reportedly affected by an as-yet
unspecified cross-site scripting vulnerability.  An attacker could
exploit this issue to steal cookie-based authentication and launch other
attacks.");
  script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/article/CTX127541");
  script_set_attribute(attribute:"solution", value:"Upgrade to Citrix Web Interface 5.4.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:web_interface");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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
paths = make_list();
key = "SOFTWARE\Citrix\Web Interface";
subkeys = get_registry_subkeys(handle:hklm, key:key);
if (!isnull(subkeys))
{
  foreach subkey (subkeys)
  {
    if (subkey =~ '^[0-9\\.]+$')
    {
      path = get_registry_value(handle:hklm, item:key + '\\' + subkey + "\Common Files Location");
    }
  }
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  audit(AUDIT_NOT_INST, 'Citrix Web Interface');
}
NetUseDel(close:FALSE);


# Determine the version info from sitemgr.exe
exe = path + "\sitemgr.exe";
ver = hotfix_get_fversion(path:exe);
hotfix_check_fversion_end();

if (ver['error'] == HCF_NOENT)
  audit(AUDIT_UNINST, 'Citrix Web Interface');
else if (ver['error'] != HCF_OK)
  audit(AUDIT_VER_FAIL, exe);

version = join(sep:'.', ver['value']);
if (version =~ '^5\\.' && ver_compare(ver:version, fix:'5.4.0', strict:FALSE) <0)
{
  if (report_verbosity > 0)
  {
    report +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.4.0.0\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, 'Citrix Web Interface', version, path);
