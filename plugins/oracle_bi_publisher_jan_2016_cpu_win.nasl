#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88104);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/04/10 14:08:53 $");

  script_cve_id(
    "CVE-2016-0470",
    "CVE-2016-0401",
    "CVE-2016-0429",
    "CVE-2016-0614"
  );
  script_bugtraq_id(
    81132,
    81147,
    81157,
    81191
  );
  script_osvdb_id(
    133200,
    133201,
    133202,
    133203
  );

  script_name(english:"Oracle Business Intelligence Publisher Multiple Vulnerabilities (January 2016 CPU)");
  script_summary(english:"Checks for applied patches.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Oracle Business Intelligence Publisher installed on the remote
host is affected by multiple vulnerabilities :

  - An unspecified vulnerability exists in the Security
    subcomponent that allows an authenticated, remote
    attacker to affect the confidentiality and integrity of
    the system. No other details are available.
    (CVE-2016-0470)

  - Multiple unspecified vulnerabilities exist in the
    Scheduler subcomponent that allow an unauthenticated,
    remote attacker to affect the integrity of the system.
    No other details are available. (CVE-2016-0401,
    CVE-2016-0429)

  - An unspecified vulnerability exists in the Security
    subcomponent that allows an authenticated, remote
    attacker to affect the confidentiality of the system.
    No other details are available. (CVE-2016-0614)");
  # https://www.oracle.com/technetwork/topics/security/cpujan2016-2367955.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d13bbe45");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2016 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:business_intelligence_publisher");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("oracle_bi_publisher_installed.nbin");
  script_require_keys("installed_sw/Oracle Business Intelligence Publisher");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("install_func.inc");
include("oracle_rdbms_cpu_func.inc");

appname = "Oracle Business Intelligence Publisher";
install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);

version = install['version'];
path = install['path'];

fixes = NULL;
bundles = make_list("None");

# Super set patches from Doc ID 1276869.1
# 11.1.1.7.0 needs either
#   BIP specific patch 22225969, which is in BI bundle 22225110, or
#   BIP specific patch 23299563, which is in BI bundle 23703041

# Super set patches from Doc ID 1276869.1
# 11.1.1.9.0 needs either
#   BIP specific patch 22382217, which is in BI bundle 22393988, or
#   BIP specific patch 22974747, which is in BI bundle 22951634, or
#   BIP specific patch 23632905, which is in BI bundle 23703078, or
#   BIP specific patch 24736889, which is in BI bundle 24668000, or
#   BIP specific patch 25214935, which is in BI bundle 25189841

# Super set patches from Doc ID 2147699.1
# 12.2.1.0.0 needs
#   BIP specific patch 22387713, or
#   BI bundle patch 22734181

if (version == "11.1.1.7.0")
{
  fixes = make_list("22225969", "23299563");
  bundles = make_list("22225110", "23703041");
}
else if (version == "11.1.1.9.0")
{
  fixes = make_list("22382217", "22974747", "23632905", "24736889", "25214935");
  bundles = make_list("22393988", "22951634", "23703078", "24668000", "25189841");
}
else if (version == "12.2.1.0.0")
  fixes = make_list("22387713", "22734181");

if (isnull(fixes)) audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);

patches = find_patches_in_ohomes(ohomes:make_list(path));

vuln = TRUE;
foreach patch (keys(patches[path]))
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
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  order = make_list("Path", "Version", "Patch required", "Bundled in");
  report = make_array(
    order[0], path,
    order[1], version,
    order[2], join(fixes, sep:" or "),
    order[3], join(bundles, sep:" or ")
  );
  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, version + ' with patch ' + fix, path);
