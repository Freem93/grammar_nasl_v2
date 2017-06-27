#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72369);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/11/13 21:13:12 $");

  script_cve_id("CVE-2013-5798");
  script_bugtraq_id(63069);
  script_osvdb_id(98465);

  script_name(english:"Oracle Identity Manager (October 2013 CPU");
  script_summary(english:"Checks for the October 2013 CPU.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by an
unspecified vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing the October 2013 Critical Patch Update for
Oracle Identity Manager. It is, therefore, affected by an unspecified
vulnerability in the End User Self Service component of the
application.");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac29c174");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2013 Critical
Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

   script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/15");
   script_set_attribute(attribute:"patch_publication_date", value:"2013/10/15");
   script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

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

if (version =~ "^11\.1\.2\.0(\.|$)")
  fixed = "11.1.2.0.10";
else if (version =~ "^11\.1\.2\.1(\.|$)")
  fixed = "11.1.2.1.2";

if (!isnull(fixed))
{
  if (ver_compare(ver:version, fix:fixed, strict:FALSE) < 0)
  {
    if (report_verbosity > 0)
    {
      report =
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fixed +
        '\n';
      security_warning(extra:report, port:0);
    }
    else security_warning(0);
    exit(0);
  }
}

audit(AUDIT_INST_PATH_NOT_VULN, product, version, path);
