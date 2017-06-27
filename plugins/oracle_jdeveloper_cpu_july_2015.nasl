#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84881);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/05/05 17:16:26 $");

  script_cve_id("CVE-2015-4742");
  script_bugtraq_id(75841);
  script_osvdb_id(124659);

  script_name(english:"Oracle JDeveloper ADF Faces DoS (July 2015 CPU)");
  script_summary(english:"Checks for the patch.");

  script_set_attribute(attribute:"synopsis", value:
"A software development application installed on the remote host is
affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle JDeveloper installed on the remote host is
missing a security patch. It is, therefore, affected by an unspecified
flaw in the Application Development Framework (ADF) Faces subcomponent
that allows an unauthenticated, remote attacker to cause a denial of
service condition.");
  # https://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f2b7623c");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2015 Oracle Critical
Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdeveloper");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

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

# If any are present, the host should be considered patched.
if (version =~ "^11\.1\.1\.7($|\.[01]$)")
  fixes = make_list('20715966', '23622763', '25252636', '25264940');
else if (version =~ "^11\.1\.2\.4($|\.0$)")
  fixes = make_list('20715992', '21773974', '23754328', '25372028', '24730407');
else if (version =~ "^12\.1\.2\.0($|\.0$)")
  fixes = make_list('20716002', '21773977');
else if (version =~ "^12\.1\.3\.0($|\.0$)")
  fixes = make_list('20716006', '21773981', '23754311', '25324374', '25635721');
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
                     "Required patch", join(fixes,sep:", ")
                    );
  order = make_list("Path", "Version", "Required patch");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
  exit(0);
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
