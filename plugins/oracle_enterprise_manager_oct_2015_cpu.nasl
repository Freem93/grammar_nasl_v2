#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86574);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/28 18:52:12 $");

  script_cve_id(
    "CVE-2015-4859",
    "CVE-2015-4874",
    "CVE-2015-4875"
  );
  script_osvdb_id(
    129089,
    129090,
    129091
  );

  script_name(english:"Oracle Enterprise Manager Agent Unspecified Vulnerabilities (October 2015 CPU)");
  script_summary(english:"Checks for the patch ID.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an enterprise management application installed
that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Enterprise Manager Agent installed on the remote
host is affected by multiple vulnerabilities :

  - An unspecified vulnerability exists in the Agent Next
    Gen subcomponent that a remote attacker can exploit to
    impact confidentiality and integrity. No other details
    are available. (CVE-2015-4859)

  - An unspecified vulnerability exists in the Agent Next
    Gen subcomponent that a local attacker can exploit to
    impact confidentiality, integrity, and availability. No
    other details are available. (CVE-2015-4874)

  - An unspecified vulnerability exists in the Agent Next
    Gen subcomponent that a remote attacker can exploit to
    impact availability. No other details are available.
    (CVE-2015-4875)");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2015-2367953.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75a4a4fb");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2015 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/23");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:enterprise_manager");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("oracle_enterprise_manager_agent_installed.nbin");
  script_require_keys("installed_sw/Oracle Enterprise Manager Agent");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("oracle_rdbms_cpu_func.inc");
include("install_func.inc");

product = "Oracle Enterprise Manager Agent";
install = get_single_install(app_name:product, exit_if_unknown_ver:TRUE);
version = install['version'];
emchome = install['path'];

if (version =~ "^12\.1\.0\.4(\.([0-4]))?$")
  patch = "21759280";
else if (version =~ "^12\.1\.0\.5(\.([0-2]))?$")
  patch = "21745074";
else
  audit(AUDIT_INST_PATH_NOT_VULN, product, version, emchome);

patchesinstalled = find_patches_in_ohomes(ohomes:make_list(emchome));

patched = FALSE;

if (!isnull(patchesinstalled))
{
  foreach patchid (keys(patchesinstalled[emchome]))
  {
    if (patchid == patch)
      patched = TRUE;
    else
    {
      foreach bugid (patchesinstalled[emchome][patchid]['bugs'])
      {
        if (bugid == patch)
        {
          patched = TRUE;
          break;
        }
      }
    }
  }
}

if (patched) audit(AUDIT_INST_PATH_NOT_VULN, product, version, emchome);

if (report_verbosity > 0)
{
  report +=
    '\n  Product       : ' + product +
    '\n  Version       : ' + version +
    '\n  Path          : ' + emchome +
    '\n  Missing patch : ' + patch +
    '\n';
  security_warning(port:0, extra:report);
}
else security_warning(0);
