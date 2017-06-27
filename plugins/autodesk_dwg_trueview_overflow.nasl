#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76308);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/30 16:45:43 $");

  script_cve_id("CVE-2013-3665");
  script_bugtraq_id(61355);
  script_osvdb_id(95384);

  script_name(english:"Autodesk DWG TrueView Buffer Overflow");
  script_summary(english:"Checks Autodesk DWG TrueView version.");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote host is affected by a buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has an install of Autodesk DWG TrueView version 2011,
2012, 2013 or 2014, and thus is affected by an error related to the
handling of DWG files.

The error exists due to a failure to properly bounds-check data in DWG
files before using it to index and copy heap memory values. An
attacker could exploit this issue by convincing a user to open a
specially crafted DWG file which could result in arbitrary code
execution.");
  script_set_attribute(attribute:"see_also", value:"http://blog.binamuse.com/2013/07/autocad-dwg-ac1021-heap-corruption.html");
  script_set_attribute(attribute:"see_also", value:"http://www.binamuse.com/advisories/BINA-20130724.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.binamuse.com/exploits/BINA-20130724.py");
  script_set_attribute(attribute:"see_also", value:"http://www.binamuse.com/papers/ACADR2007Report.pdf");
  # http://knowledge.autodesk.com/support/dwg-trueview/downloads/caas/downloads/content/autodesk-C2-AE-autocad-C2-AE-code-execution-vulnerability--E2-80-93-security-hotfix.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f980a90d");
  # http://knowledge.autodesk.com/sites/default/files/file_downloads/AutoCAD_Code_Execution_Readme.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e641599");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 18.1.75.0.0, 18.2.75.0.0, 19.0.75.0.0, 19.1.75.0.0
or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:dwg_trueview");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("autodesk_dwg_trueview_installed.nbin");
  script_require_keys("SMB/Autodesk DWG TrueView/Installed");
  script_require_ports(139, 445);
  exit(0);

}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Autodesk DWG TrueView/Installed");
installs = get_kb_list_or_exit("SMB/Autodesk DWG TrueView/*/Version");
kb_entry = branch(keys(installs));
kb_base = kb_entry - "/Version";

prod_version = get_kb_item_or_exit(kb_entry);

path = get_kb_item_or_exit(kb_base + "/Path");
display_name = get_kb_item_or_exit(kb_base + "/Display_Name");

pieces = split(prod_version, sep:".", keep:FALSE);
major_ver = pieces[0];

# Check acdb.dll file version
exe = path + "\acdb" + major_ver + ".dll";
ver = hotfix_get_pversion(path:exe);
err_res = hotfix_handle_error(
  error_code   : ver['error'],
  file         : exe,
  appname      : display_name,
  exit_on_fail : TRUE
);
hotfix_check_fversion_end();

version = ver['value'];
fixed_version = FALSE;

# TrueView 2011 (18.1.0.0 and up)
if (version =~ "^18\.1\." && ver_compare(ver:version, fix:"18.1.75.0.0", strict:FALSE) < 0) 
  fixed_version = '18.1.75.0.0';

# TrueView 2012
else if (version =~ "^18\.2" && ver_compare(ver:version, fix:"18.2.75.0.0", strict:FALSE) < 0) 
  fixed_version = '18.2.75.0.0';

# TrueView 2013
else if (version =~ "^19\.0" && ver_compare(ver:version, fix:"19.0.75.0.0", strict:FALSE) < 0) 
  fixed_version = '19.0.75.0.0';

# TrueView 2014
else if (version =~ "^19\.1" && ver_compare(ver:version, fix:"19.1.75.0.0", strict:FALSE) < 0) 
  fixed_version = '19.1.75.0.0';


if (fixed_version)
{
  port = kb_smb_transport();

  if (report_verbosity > 0)
  {
    report += '\n  Product           : ' + display_name +
              '\n  Path              : ' + exe +
              '\n  Installed version : ' + version +
              '\n  Fixed version     : ' + fixed_version + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_VER_NOT_VULN, exe, version);
