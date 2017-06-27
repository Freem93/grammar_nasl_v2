#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74154);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/05/30 19:48:03 $");

  script_cve_id("CVE-2014-3802");
  script_bugtraq_id(67398);
  script_osvdb_id(106963);

  script_name(english:"MS KB2927432: Visual Studio Update 2 for Debug Interface Access SDK");
  script_summary(english:"Checks version of msdia.dll.");

  script_set_attribute(attribute:"synopsis", value:
"An SDK library on the remote Windows host is affected by a memory
corruption vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Microsoft Debug Interface Access Library on the
remote host is affected by a memory corruption vulnerability related
to parsing PDB files. An attacker could exploit this issue by tricking
a user into loading a malicious file. This could allow an attacker to
execute arbitrary code or cause a denial of service condition.

This issue is believed to be fixed in Visual Studio 2013 Update 2.
Please see Microsoft knowledge base article 2927432 for more details.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-129/");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/2927432");
  script_set_attribute(attribute:"solution", value:"Upgrade to Microsoft Visual Studio 2013 Update 2. See KB2927432.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

product_name = "Visual Studio 2013";
component_name = "Debug Interface Access Library";
full_name = product_name + " " + component_name;

install_path_key = "SOFTWARE\Microsoft\VisualStudio\12.0\Setup\VS\ProductDir";
file_path = "Common7\Packages\Debugger\msdia120.dll";

port = kb_smb_transport();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
install_path = get_registry_value(handle:hklm, item:install_path_key);
RegCloseKey(handle:hklm);

if (isnull(install_path))
{
  close_registry();
  audit(AUDIT_NOT_INST, product_name);
}
close_registry(close:FALSE);

path = install_path + file_path;

if (!hotfix_file_exists(path:path))
{
  hotfix_check_fversion_end();
  audit(AUDIT_NOT_INST, full_name);
}

ver = hotfix_get_fversion(path:path);
hotfix_check_fversion_end();
if (ver['error'] != HCF_OK)
  audit(AUDIT_VER_FAIL, path);

ver = join(ver['value'], sep:'.');

fix = "12.0.30501.0";
if (ver_compare(ver:ver, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Product           : ' + full_name +
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';

    security_warning(port:port, extra:report);
  }
  else security_warning(port:port);
}
else audit(AUDIT_INST_VER_NOT_VULN, full_name, ver);
