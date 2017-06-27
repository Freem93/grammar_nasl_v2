#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81342);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/07/07 21:05:39 $");

  script_cve_id("CVE-2015-0517", "CVE-2015-0518");
  script_bugtraq_id(72501, 72502);
  script_osvdb_id(117938, 117939);

  script_name(english:"EMC Documentum D2 < 4.1 P22 / 4.2 P11 Multiple Vulnerabilities (ESA-2015-010)");
  script_summary(english:"Checks the version of Documentum D2.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version EMC Documentum D2 prior to 4.1
P22 / 4.2 P11. It is, therefore, affected by multiple vulnerabilities
:

  - An information disclosure vulnerability exists due to
    the D2-API component logging the MD5 hash of the
    passphrase used to encrypt sensitive information and
    user credentials. A remote, authenticated attacker can
    recover the passphrase. (CVE-2015-0517)

  - A privilege escalation vulnerability exists due to a
    flaw in the D2FS web service component that allows a
    remote, authenticated attacker to manipulate group
    permissions and obtain superuser privileges.
    (CVE-2015-0518)");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2015/Feb/att-30/ESA-2015-010.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to EMC Documentum D2 4.1 P22 / 4.2 P11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:documentum_d2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencies("emc_documentum_d2_detect.nbin");
  script_require_keys("installed_sw/EMC Documentum D2");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app_name = "EMC Documentum D2";
get_install_count(app_name:app_name, exit_if_zero:TRUE);

port = get_http_port(default:8080);
install = get_single_install(app_name:app_name, port:port, exit_if_unknown_ver:TRUE);
url = build_url(port:port, qs:install['path']);
version = install['version'];
display_version = install['display_version'];
fix = NULL;
fix_display = NULL;

# Version 3.1: patch is not available - must upgrade
if(version =~ "^3\.1\.")
{
  fix = "999";
  fix_display = "4.2.0110 Build 0525 (4.2 P11)";
}
# Version 4.0: patch is not available - must upgrade
else if(version =~ "^4\.0\.")
{
  fix = "999";
  fix_display = "4.2.0110 Build 0525 (4.2 P11)";
}
else if(version =~ "^4\.1\.")
{
  fix = "4.1.0220.0575";
  fix_display = "4.1.0220 Build 0575 (4.1 P22)";
}
else if(version =~ "^4\.2\.")
{
  fix = "4.2.0110.0525";
  fix_display = "4.2.0110 Build 0525 (4.2 P11)";
}

if (fix && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL           : ' + build_url(port:port, qs:install['path']) +
      '\n  Version       : ' + install['display_version'] +
      '\n  Fixed version : ' + fix_display +
      '\n';

    security_warning(extra:report, port:port);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url, display_version);
