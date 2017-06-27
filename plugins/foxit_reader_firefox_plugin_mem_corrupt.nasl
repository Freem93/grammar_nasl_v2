#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43029);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/19 01:42:50 $");

  script_bugtraq_id(36673);
  script_osvdb_id(58953);
  script_xref(name:"Secunia", value:"37049");

  script_name(english:"Foxit Reader Firefox Plugin Reloading RCE");
  script_summary(english:"Checks the version of Foxit Reader and its Firefox plugin.");

  script_set_attribute(attribute:"synopsis", value:
"A PDF viewer installed on the remote host is affected by a remote
code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit Reader installed on the remote
Windows host is affected by an memory corruption issue related to the
Firefox plugin (npFoxitReaderPlugin.dll). An unauthenticated, remote
attacker can exploit this to execute arbitrary code, by tricking a
user into loading a specially crafted web page that repeatedly loads
and unloads the plugin.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2009/Oct/198");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2009/Oct/204");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2009/Nov/211");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit Reader version 3.1.3.1030, and install the latest
Firefox Plugin via the internal update mechanism.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:foxit_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("foxit_reader_installed.nasl", "mozilla_org_installed.nasl");
  script_require_keys("installed_sw/Mozilla Firefox", "installed_sw/Foxit Reader");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("install_func.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_reg_query.inc");
include("smb_hotfixes_fcheck.inc");

ff = "Mozilla Firefox";
fr = "Foxit Reader";

get_install_count(app_name:ff, exit_if_zero:TRUE);
get_install_count(app_name:fr, exit_if_zero:TRUE);

# Leverage the FF install to find the plugins path without additional registry enumeration
ff_install = get_single_install(app_name:ff, exit_if_unknown_ver:TRUE);
ff_path = ff_install['path'];

# Check the version of Foxit Reader without checking the plugin version for non-paranoid
fr_install = get_single_install(app_name:fr, exit_if_unknown_ver:TRUE);
fr_version = fr_install['version'];
fr_path = fr_path['path'];

# nb: the vendor's advisory only lists as affected
#     Foxit Reader 3.1.2.1013 and Foxit Reader 3.1.3.1030.
if (report_paranoia < 2)
{
  if (fr_version != "3.1.2.1013" &&
      fr_version != "3.1.3.1030")
    audit(AUDIT_INST_PATH_NOT_VULN, fr, fr_version, fr_path);
}

fixed_version = "1.0.1.1111";
plugin_path = ff_path + "\plugins\npFoxitReaderPlugin.dll";

plugin_version = hotfix_get_fversion(path:plugin_path);
if (plugin_version['error'] != HCF_OK)
{
  hotfix_handle_error(error_code: plugin_version['error'],
                      file: 'npFoxitReaderPlugin.dll',
                      appname: 'Foxit Reader Plugin',
                      exit_on_fail: TRUE);
}

hotfix_check_fversion_end();
plugin_version = join(plugin_version['value'], sep:'.');

report = NULL;
if (ver_compare(ver:plugin_version, fix:fixed_version) < 0)
{
  port = get_kb_item('SMB/transport');
  if (!port)
    port = 445;

  report =
    '\n  Plugin path    : ' + plugin_path +
    '\n  Plugin version : ' + plugin_version +
    '\n  Fixed version  : ' + fixed_version +
    '\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);

}
else
  audit(AUDIT_INST_PATH_NOT_VULN, fr, fr_version, fr_path);
