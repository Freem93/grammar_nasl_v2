#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90706);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/03/22 19:26:12 $");

  script_cve_id("CVE-2015-8035");
  script_bugtraq_id(77390);
  script_osvdb_id(129696);

  script_name(english:"Tenable Log Correlation Engine (LCE) < 4.8.0 Libxml2 DoS");
  script_summary(english:"Performs a version check.");

  script_set_attribute(attribute:"synopsis", value:
"A data aggregation application installed on the remote host is
affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Tenable Log Correlation Engine (LCE) installed on the
remote host is a version prior to 4.8.0. It is, therefore, affected by
a denial of service vulnerability in the bundled version of Libxml2
due to an infinite loop condition in the xz_decomp() function. An
unauthenticated, remote attacker can exploit this by convincing a user
to input specially crafted XML content, to exhaust available system
resources, resulting in a denial of service condition.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2016-06");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2015/q4/206");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable LCE version 4.8.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:log_correlation_engine");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("lce_installed.nbin");
  script_require_keys("installed_sw/Log Correlation Engine Server");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");

app_name = "Log Correlation Engine Server";

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version = install['version'];
path    = install['path'];

fixed_version = '4.8.0';

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  security_report_v4(
    port:0,
    severity:SECURITY_WARNING,
    extra:
      '\n  Path               : ' + path +
      '\n  Installed version  : ' + version +
      '\n  Fixed version      : ' + fixed_version +
      '\n'
  );
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
