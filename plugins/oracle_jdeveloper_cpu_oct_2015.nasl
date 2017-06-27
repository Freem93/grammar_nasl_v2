#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86545);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/05/05 17:16:26 $");

  script_cve_id("CVE-2015-4838", "CVE-2015-4909");
  script_bugtraq_id(77167, 77174);
  script_osvdb_id(129074, 129081);

  script_name(english:"Oracle JDeveloper Multiple Vulnerabilities (October 2015 CPU)");
  script_summary(english:"Checks for patch.");

  script_set_attribute(attribute:"synopsis", value:
"A software development application installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle JDeveloper installed on the remote host is
missing a security patch. It is, therefore, affected by multiple
vulnerabilities :

  - An unspecified flaw exists in the ADF Faces subcomponent
    that allows an authenticated, remote attacker to
    disclose sensitive information. (CVE-2015-4838)

  - An unspecified flaw exists in the ADF Faces subcomponent
    that allows an unauthenticated, remote attacker to
    impact integrity. (CVE-2015-4909)");
  # https://www.oracle.com/technetwork/topics/security/cpuoct2015-2367953.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?404a1fb9");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2015 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/22");

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

# JDeveloper has two install modes: OUI and SA.
#  - OUI mode behaves like other Oracle products and uses the path
#    found in C:\bea\beahomelist. This is where we historically have
#    gathered the path to search for patches.
#  - SA mode stores the patch information in a product specific
#    directory, a subdirectory of common path for Oracle products.
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

if (version =~ "^11\.1\.2\.4($|\.0$)")
  fixes = make_list('21773974', '23754328', '25372028', '24730407');
else if (version =~ "^12\.1\.2\.0($|\.0$)")
  fixes = make_list('21773977');
else if (version =~ "^12\.1\.3\.0($|\.0$)")
  fixes = make_list('21773981', '23754311', '25324374', '25635721');
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
  items = make_array(
    "Path", path,
    "Version", version,
    "Required patch", "Refer to October 2015 CPU"
  );

  order = make_list("Path", "Version", "Required patch");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
