#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78542);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/07 20:46:55 $");

  script_cve_id("CVE-2014-0114", "CVE-2014-2880", "CVE-2014-6487");
  script_bugtraq_id(66615, 67121, 70458);
  script_osvdb_id(105384, 106409, 113278);
  script_xref(name:"EDB-ID", value:"32670");

  script_name(english:"Oracle Identity Manager (October 2014 CPU");
  script_summary(english:"Checks for the October 2014 CPU.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing the October 2014 Critical Patch Update for
Oracle Identity Manager. It is, therefore, affected by multiple
vulnerabilities :

  - The application is affected by a vulnerability in
    Apache Commons BeanUtils in which ClassLoader objects
    can be set via the class attribute of an ActionForm
    object. This can be used to manipulate the ClassLoader
    or execute arbitrary code. (CVE-2014-0114)

  - The application is subject to a cross-site redirection
    attack because user-supplied input to the 'backUrl'
    parameter is not properly validated. (CVE-2014-2880)

  - An unspecified vulnerability exists in the End User
    Self Service component. (CVE-2014-6487).");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2014-1972960.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6dcc7b47");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2014 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts ClassLoader Manipulation Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:identity_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("oracle_identity_management_installed.nbin");
  script_require_keys("installed_sw/Oracle Identity Manager");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("oracle_rdbms_cpu_func.inc");
include("misc_func.inc");
include("install_func.inc");

product = "Oracle Identity Manager";
install = get_single_install(app_name:product, exit_if_unknown_ver:TRUE);

version = install['version'];
path = install['path'];

fixed = NULL;
patch = NULL;
report = NULL;

if (version =~ "^11\.1\.1\.7(\.[01])?$")
  patch = '19666962';
else if (version =~ "^11\.1\.1\.5(\.[0-9]|\.1[01])?$")
  patch = '19696852';
else if (version =~ "^11\.1\.2\.1(\.0|$)")
  fix = '11.1.2.1.9';
else if (version =~ "^11\.1\.2\.2(\.0|$)")
  fix = '11.1.2.2.4';

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

if (report_verbosity > 0) security_hole(port:0, extra:report);
else security_hole(port:0);
