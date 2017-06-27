#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84640);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/07/10 14:11:55 $");

  script_cve_id("CVE-2015-0547", "CVE-2015-0548");
  script_bugtraq_id(75517);
  script_osvdb_id(124015, 124016);

  script_name(english:"EMC Documentum D2 4.1 / 4.2.x < 4.2 P16 / 4.5.x < 4.5 P03 Multiple DQL Injection Vulnerabilities");
  script_summary(english:"Checks the EMC Documentum version.");

  script_set_attribute(attribute:"synopsis",value:
"The remote host is affected by multiple DQL injection vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The EMC Documentum D2 running on the remote host is affected by DQL
injection vulnerabilities in the D2CenterstageService.getComments and
D2DownloadService.getDownloadUrls services due to a failure to
sanitize user-supplied input. A remote, authenticated attacker can
exploit these to bypass read-access restrictions, allowing the
disclosure of sensitive data in the database.");
  script_set_attribute(attribute:"see_also",value:"http://seclists.org/bugtraq/2015/Jul/att-10/ESA-2015-108.txt");
  script_set_attribute(attribute:"solution",value:
"Upgrade to EMC D2 Documentum 4.2 P16 / 4.5 P03 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/07/01");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/09");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:emc:documentum_d2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

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

if(version =~ "^4\.1\.")
{
  fix = "999";
  fix_display = "4.2.0160 Build 0576 (4.2 P16)";
}
else if(version =~ "^4\.2\.")
{
  fix = "4.2.0160.0576";
  fix_display = "4.2.0160 Build 0576 (4.2 P16)";
}
else if(version =~ "^4\.5\.")
{
  fix = "4.5.0030.0448";
  fix_display = "4.5.0030 Build 0448 (4.5 P03)";
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
