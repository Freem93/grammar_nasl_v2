#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86541);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/04/12 14:39:07 $");

  script_cve_id("CVE-2015-4832");
  script_bugtraq_id(77201);
  script_osvdb_id(129077);

  script_name(english:"Oracle Identity Manager OIM Legacy UI Unspecified Vulnerability (October 2015 CPU)");
  script_summary(english:"Checks for the October 2015 CPU.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by an
unspecified vulnerability that impacts integrity.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing the October 2015 Critical Patch Update for
Oracle Identity Manager. It is, therefore, affected by an unspecified
vulnerability due to an unspecified flaw in the OIM Legacy UI
subcomponent. A remote attacker can exploit this flaw to impact
integrity.");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2015-2367953.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75a4a4fb");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2015 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:identity_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("oracle_identity_management_installed.nbin");
  script_require_keys("installed_sw/Oracle Identity Manager");

  exit(0);
}

include("global_settings.inc");
include("oracle_rdbms_cpu_func.inc");
include("misc_func.inc");
include("install_func.inc");

product = "Oracle Identity Manager";
install = get_single_install(app_name:product, exit_if_unknown_ver:TRUE);

version = install['version'];
path = install['path'];

fixed = NULL;
report = NULL;

if (version =~ "^11\.1\.1\.7(\.[01])?$")
  fixed = '11.1.1.7.2';
else if (version =~ "^11\.1\.2\.3(\.[0-3])?$")
  fixed = '11.1.2.3.4';
else if (version =~ "^11\.1\.2\.2(\.[0-7])?$")
  fixed = '11.1.2.2.8';

if (!isnull(fixed))
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
