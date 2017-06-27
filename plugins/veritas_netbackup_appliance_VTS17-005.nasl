#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100273);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/05/26 15:50:24 $");

  script_cve_id("CVE-2017-8859");
  script_bugtraq_id(98383);
  script_osvdb_id(157138);
  script_xref(name:"IAVA", value:"2017-A-0152");

  script_name(english:"Veritas NetBackup Appliance 2.7.x / 3.0.x Remote Command Execution (VTS17-005)");
  script_summary(english:"Checks the version of NetBackup Appliance.");

  script_set_attribute(attribute:"synopsis", value:
"The remote backup management appliance is affected by a remote command
execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote Veritas NetBackup
Appliance is 2.7.x or 3.0.x, and may be missing a vendor-supplied
security patch. It is, therefore, affected by a remote command
execution vulnerability due to improper validation of user-supplied
input. An unauthenticated, remote attacker can exploit this to execute
arbitrary commands with root privileges.

Note that Nessus has not checked to see if an available Emergency
Engineering Binary (EEB) was applied.");
  script_set_attribute(attribute:"see_also", value:"https://www.veritas.com/content/support/en_US/security/VTS17-005.html");
  script_set_attribute(attribute:"see_also", value:"https://www.veritas.com/support/en_US/article.000126557");
  script_set_attribute(attribute:"solution", value:
"Apply the May 7th Emergency Engineering Binary (EEB) as referenced in
the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:veritas:netbackup_appliance");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("veritas_netbackup_appliance_web_console_detect.nbin");
  script_require_keys("installed_sw/NetBackup Appliance", "Settings/ParanoidReport");

  exit(0);
}

include("vcf.inc");
include("http.inc");

port = get_http_port(default:443);
if(!port) port = 443;

app_info = vcf::get_app_info(app:"NetBackup Appliance", webapp:true, port:port);

# If the version is less than the fixed version it may still be patched.
# Hotfixes were released for 7.7.2 and 7.7.3, so only run on paranoid.
if(report_paranoia < 2)
  audit(AUDIT_PARANOID);
if( app_info.version =~ "^2\.")
{
  vcf::check_granularity(app_info:app_info, sig_segments:3);
}
else if (app_info.version =~ "^3\.")
{
  vcf::check_granularity(app_info:app_info, sig_segments:2);
}



constraints = [
  { "min_version" : "2.7.0", "max_version" : "2.7.2", "fixed_version" : "2.7.4", "fixed_display" : "ET3916411"},
  { "equal" : "2.7.3", "fixed_version" : "2.7.4", "fixed_display" : "ET3916412"},
  { "equal" : "3.0.0", "fixed_version" : "3.0.1", "fixed_display" : "ET3916413"}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
