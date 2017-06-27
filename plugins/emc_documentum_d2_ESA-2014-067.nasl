#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77304);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/02/18 15:00:16 $");

  script_cve_id("CVE-2014-2515");
  script_bugtraq_id(69275);
  script_osvdb_id(110019);

  script_name(english:"EMC Documentum D2 Privilege Escalation (ESA-2014-067)");
  script_summary(english:"Checks for Documentum D2.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running EMC Documentum D2. It is, therefore,
affected by a privilege escalation vulnerability due to a flaw in the
'D2GetAdminTicketMethod' and 'D2RefreshCacheMethod' methods. A remote,
authenticated attacker can exploit these methods to obtain superuser
privileges.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2014/Aug/att-92/ESA-2014-067.txt");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:documentum_d2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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

# We flag 3.1 on paranoid scans since we don't how version numbers
# work there.
if (version =~ "^3\.1\." && report_paranoia > 1)
{
  fix = "999";
  fix_display = "3.1P24 / 3.1SP1P02";
}
else if (version =~ "^4\.0\.")
{
  # We don't know what a hotfix looks like so we're only going to flag this if the version is below
  # 4.0P11 or if running a paranoid scan (in which case 4.0P11 will also be flagged).
  if (report_paranoia > 1 || ver_compare(ver:version, fix:'4.0.110', strict:FALSE) == -1)
  {
    fix = "4.0.120";
    fix_display = "4.0P11 (Hotfix)";
  }
}
else if (version =~ "^4\.1\.")
{
  fix = "4.1.0160.0542";
  fix_display = "4.1.0160 Build 0542 (4.1P16)";
}
else if (version =~ "^4\.2\.")
{
  fix = "4.2.0050.0440";
  fix_display = "4.2.0050 Build 0440 (4.2P05)";
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

    security_hole(extra:report, port:port);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url, display_version);
