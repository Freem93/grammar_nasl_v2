#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96657);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/05/05 17:16:26 $");

  script_cve_id("CVE-2017-3255");
  script_bugtraq_id(95543);
  script_osvdb_id(150445);

  script_name(english:"Oracle JDeveloper ADF Faces Unspecified Remote Information Disclosure (January 2017 CPU)");
  script_summary(english:"Checks for the patch.");

  script_set_attribute(attribute:"synopsis", value:
"A software development application installed on the remote host is
affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle JDeveloper installed on the remote host is
missing a security patch. It is, therefore, affected by an information
disclosure vulnerability in the Application Development Framework
(ADF) Faces subcomponent that allows an unauthenticated, remote
attacker to disclose arbitrary data.");
  # http://www.oracle.com/technetwork/security-advisory/cpujan2017-2881727.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?89a8e429");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2017 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdeveloper");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("oracle_jdeveloper_installed.nbin");
  script_require_keys("installed_sw/Oracle JDeveloper");

  exit(0);
}

include("global_settings.inc");
include("oracle_rdbms_cpu_func.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "Oracle JDeveloper";
install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version = install['version'];
path = install['path'];

patch_info = find_patches_in_ohomes(ohomes:make_list(path, path + "\jdeveloper"));
patches = make_list();

# this is the resulting list of ohomes
foreach ohome (keys(patch_info))
{
  # these are the patches enumerated from each ohome
  foreach info (keys(patch_info[ohome]))
  {
    # build a list of all patches in all ohomes to test against
    patches = make_list(patches, info);
  }
}

fixes = NULL;

if (version =~ "^11\.1\.1\.7($|\.[01]$)")
  fixes = make_list('25264940');
else if (version =~ "^11\.1\.1\.9($|\.0$)")
  fixes = make_list('25245227');
else if (version =~ "^11\.1\.2\.4($|\.0$)")
  fixes = make_list('25372028', '24730407');
else if (version =~ "^12\.1\.3\.0($|\.0$)")
  fixes = make_list('25324374', '25635721');
else if (version =~ "^12\.2\.1\.0($|\.0$)")
  fixes = make_list('25335432', '25637372');
else if (version =~ "^12\.2\.1\.1($|\.0$)")
  fixes = make_list('25242617', '25639913');
else
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

vuln = TRUE;
foreach patch (patches)
{
  foreach fix (fixes)
  {
    if (patch == fix)
    {
      vuln = FALSE;
      break;
    }
  }
  if (!vuln) break;
}

if (vuln)
{
  items = make_array("Path", path,
                     "Version", version,
                     "Required patch", join(fixes, sep:", ")
                    );
  order = make_list("Path", "Version", "Required patch");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
  exit(0);
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
