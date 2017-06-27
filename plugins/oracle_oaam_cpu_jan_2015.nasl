#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80997);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/04/18 18:41:38 $");

  script_cve_id("CVE-2014-6576");
  script_bugtraq_id(72152);
  script_osvdb_id(117252);

  script_name(english:"Oracle Adaptive Access Manager Unspecified Remote Vulnerability (January 2015 CPU)");
  script_summary(english:"Checks for the patch.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by an unspecified vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of Oracle Adaptive Access Manager
installed that is affected by an unspecified remote vulnerability in
the OAM Integration subcomponent, which can be exploited by a remote,
authenticated user to impact confidentiality and integrity.");
  # http://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c02f1515");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2015 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("oracle_adaptive_access_manager_installed.nbin");
  script_require_keys("installed_sw/Oracle Adaptive Access Manager");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("oracle_rdbms_cpu_func.inc");
include("misc_func.inc");
include("install_func.inc");

product = "Oracle Adaptive Access Manager";
install = get_single_install(app_name:product, exit_if_unknown_ver:TRUE);

version = install['version'];
path = install['path'];

fixed = NULL;
patch = NULL;
report = NULL;

if (version =~ "^11\.1\.1\.5(\.|$)")
  fixed = "11.1.1.5.4";
else if (version =~ "^11\.1\.1\.7(\.0|$)")
  patch = '20060599';

if (!isnull(patch))
{
  patches = find_patches_in_ohomes(ohomes:make_list(path));

  vuln = TRUE;
  if (!empty_or_null(patches))
    if (!isnull(patches[path][patch])) vuln = FALSE;

  if (vuln)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Required patch    : ' + patch +
      '\n';
  }
}
else if (!isnull(fixed))
{
  if (ver_compare(ver:version, fix:fixed, strict:FALSE) < 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed +
      '\n';
  }
}

if (isnull(report)) audit(AUDIT_INST_PATH_NOT_VULN, product, version, path);

if (report_verbosity > 0) security_warning(port:0, extra:report);
else security_warning(port:0);
