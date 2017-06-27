#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100272);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/05/18 21:06:11 $");

  script_cve_id(
    "CVE-2017-8856",
    "CVE-2017-8857",
    "CVE-2017-8858"
  );
  script_bugtraq_id(
    98379,
    98381,
    98384
  );
  script_osvdb_id(
    157127,
    157128,
    157129
  );
  script_xref(name:"IAVA", value:"2017-A-0152");

  script_name(english:"Veritas NetBackup 7.7.x / 8.0.x Multiple Vulnerabilities (VTS17-004)");
  script_summary(english:"Checks the version and hotfixes of NetBackup.");

  script_set_attribute(attribute:"synopsis", value:
"A back-up management application installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Veritas NetBackup application installed on the remote Windows host
is 7.7.x or 8.0.x and may be missing a vendor-supplied security
hotfix. It is, therefore, affected by multiple vulnerabilities :

  - A remote command execution vulnerability exists in the
    bprd process due to improper directory whitelisting
    protections. An unauthenticated, remote attacker can
    exploit this to execute arbitrary commands with root or
    administrator privileges. (CVE-2017-8856)

  - A remote command execution vulnerability exists in the
    bprd process due to a flaw that allows copying arbitrary
    files on any NetBackup host in the master server domain.
    An unauthenticated, remote attacker can exploit this to
    execute arbitrary commands with root or administrator
    privileges. (CVE-2017-8857)

  - A remote code execution vulnerability exists in the bprd
    process due to a flaw that allows the writing of
    arbitrary files to a host in the master server domain.
    An unauthenticated, remote attacker can exploit this to
    execute arbitrary code. (CVE-2017-8858)

Note that Nessus has not checked to see if an available Emergency
Engineering Binary (EEB) or hotfix was applied.");
  script_set_attribute(attribute:"see_also", value:"https://www.veritas.com/content/support/en_US/security/VTS17-004.html");
  script_set_attribute(attribute:"see_also", value:"https://www.veritas.com/support/en_US/article.000126389");
  script_set_attribute(attribute:"solution", value:
"Apply the Emergency Engineering Binary (EEB) / security hotfix as
referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:veritas:netbackup");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("veritas_netbackup_installed.nbin");
  script_require_keys("installed_sw/NetBackup", "Settings/ParanoidReport");

  exit(0);
}

include("vcf.inc");


app_info = vcf::get_app_info(app:"NetBackup", win_local:TRUE);

# If the version is less than the fixed version it may still be patched.
# Hotfixes were released for 7.7.2, 7.7.3, and 8.0, so only run on paranoid.
if(report_paranoia < 2)
  audit(AUDIT_PARANOID);
if( app_info.version =~ "^7\.")
{
  vcf::check_granularity(app_info:app_info, sig_segments:3);
}
else if (app_info.version =~ "^8\.")
{
  vcf::check_granularity(app_info:app_info, sig_segments:2);
}

constraints = [
  { "min_version" : "7.7.0", "max_version" : "7.7.2", "fixed_version" : "7.7.4", "fixed_display" : "ET3913179"},
  { "equal" : "7.7.3", "fixed_version" : "7.7.4", "fixed_display" : "ET3912471"},
  { "equal" : "8.0.0", "fixed_version" : "8.0.1", "fixed_display" : "ET3912472"}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
