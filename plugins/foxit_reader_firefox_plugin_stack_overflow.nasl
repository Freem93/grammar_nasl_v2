#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64094);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/03/07 16:39:32 $");

  script_bugtraq_id(57174);
  script_osvdb_id(89030);
  script_xref(name:"EDB-ID", value:"23944");
  script_xref(name:"EDB-ID", value:"24502");

  script_name(english:"Foxit Reader Firefox Plugin URL File Name RCE");
  script_summary(english:"Checks the version of Foxit Reader and its Firefox plugin.");

  script_set_attribute(attribute:"synopsis", value:
"A PDF viewer installed on the remote host is affected by a remote
code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit Reader installed on the remote
Windows host is affected by an boundary error related to the Firefox
plugin (npFoxitReaderPlugin.dll) due to improper processing of
user-supplied input when handing an overly long file name in a URL
query string. An unauthenticated, remote attacker can exploit this,
via a crafted URL, to trigger a stack-based buffer overflow, resulting
in a denial of service or the execution of arbitrary code.");
  # https://web.archive.org/web/20130111032720/http://retrogod.altervista.org/9sg_foxit_overflow.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7497e804");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit Reader version 5.4.5.0114, and install the latest
Firefox Plugin via the internal update mechanism.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Foxit Reader Plugin URL Processing Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:foxit_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

# previous to 5.4.5 is vuln.
if (report_paranoia < 2)
{
  if (ver_compare(ver:fr_version, fix:"5.4.5", strict:FALSE) >= 0)
    audit(AUDIT_INST_PATH_NOT_VULN, fr, fr_version, fr_path);
}

fixed_version = "2.2.3.111";

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
  port = kb_smb_transport();

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
