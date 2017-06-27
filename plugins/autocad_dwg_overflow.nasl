#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73292);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/05/05 20:35:56 $");

  script_cve_id("CVE-2013-3665");
  script_bugtraq_id(61355);
  script_osvdb_id(95384);

  script_name(english:"Autodesk AutoCAD DWG Buffer Overflow");
  script_summary(english:"Checks Autodesk AutoCAD version");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote host is affected by a buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of Autodesk AutoCAD installed that is
potentially affected by an error related to handling DWG files that
could lead to buffer overflows and possibly arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"http://blog.binamuse.com/2013/07/autocad-dwg-ac1021-heap-corruption.html");
  script_set_attribute(attribute:"see_also", value:"http://www.binamuse.com/advisories/BINA-20130724.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.binamuse.com/exploits/BINA-20130724.py");
  script_set_attribute(attribute:"see_also", value:"http://www.binamuse.com/papers/ACADR2007Report.pdf");
  # http://knowledge.autodesk.com/support/autocad/downloads/caas/downloads/content/autodesk-C2-AE-autocad-C2-AE-code-execution-vulnerability--E2-80-93-security-hotfix.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?add64eae");
  script_set_attribute(attribute:"solution", value:
"Apply the patch provided by the vendor. Note that :

  - AutoCAD 2011 Service Pack 2 is a pre-requisite to apply the patch.

  - AutoCAD 2012 Service Pack 2 is a pre-requisite to apply the patch.

  - AutoCAD 2013 Service Pack 2 is a pre-requisite to apply the patch.

  - AutoCAD 2014 Service Pack 1 contains the patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:autocad");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:autocad_architecture");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:autocad_civil_3d");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:autocad_ecscad");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:autocad_electrical");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:autocad_lt");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:autocad_map_3d");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:autocad_mechanical");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:autocad_mep");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:autocad_p%26id");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:autocad_plant_3d");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:autocad_structural_detailing");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:autocad_utility_design");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("autocad_installed.nbin");
  script_require_keys("SMB/Autodesk AutoCAD/Installed");
  script_require_ports(139, 445);
  exit(0);

}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Autodesk AutoCAD/Installed");
installs = get_kb_list_or_exit("SMB/Autodesk AutoCAD/*/Version");
kb_entry = branch(keys(installs));
kb_base = kb_entry - "/Version";

prod_version = get_kb_item_or_exit(kb_entry);

path = get_kb_item_or_exit(kb_base + "/Path");
display_name = get_kb_item_or_exit(kb_base + "/Display_Name");

sp  = get_kb_item(kb_base + "/SP");
if (isnull(sp)) sp = '';
else sp = ' ' + sp;

pieces = split(prod_version, sep:".", keep:FALSE);
major_ver = pieces[0];
major_ver = major_ver - 'R';

# Check acdb.dll file version
exe = path + "\acdb" + major_ver + ".dll";
ver = hotfix_get_pversion(path:exe);
err_res = hotfix_handle_error(
  error_code   : ver['error'],
  file         : exe,
  appname      : display_name + sp,
  exit_on_fail : TRUE
);
hotfix_check_fversion_end();

version = ver['value'];
fixed_version = FALSE;

# AutoCAD 2011 (note: must be Update 2 in order to patch)
# and earlier
if (
  version =~ "^(17|18\.[01])\." &&
  ver_compare(ver:version, fix:"18.1.250.0", strict:FALSE) < 0
  )
  fixed_version = '18.1.250.0';

# AutoCAD 2012 (note: must be Service Pack 2 in order to patch)
else if (
  version =~ "^18\.2" &&
  ver_compare(ver:version, fix:"18.2.250.0", strict:FALSE) < 0
  )
  fixed_version = '18.2.250.0';

# AutoCAD 2013 (note: must be Service Pack 2 in order to patch)
else if (
  version =~ "^19\.0" &&
  ver_compare(ver:version, fix:"19.0.250.0", strict:FALSE) < 0
  )
  fixed_version = '19.0.250.0';

# AutoCAD 2014
else if (
  version =~ "^19\.1" &&
  ver_compare(ver:version, fix:"19.1.75.0", strict:FALSE) < 0
  )
  fixed_version = '19.1.75.0';

if (fixed_version)
{
  port = kb_smb_transport();

  if (report_verbosity > 0)
  {
    report += '\n  Product           : ' + display_name + sp +
              '\n  Path              : ' + exe +
              '\n  Installed version : ' + version +
              '\n  Fixed version     : ' + fixed_version + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_VER_NOT_VULN, exe, version);
