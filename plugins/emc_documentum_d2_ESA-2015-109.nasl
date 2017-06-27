#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84402);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/10 04:41:16 $");

  script_cve_id("CVE-2015-0549");
  script_osvdb_id(123617);

  script_name(english:"EMC Documentum D2 4.1.x < 4.5 XSS (ESA-2015-109)");
  script_summary(english:"Checks the version of Documentum D2.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version EMC Documentum D2 that is 4.1.x
or 4.2.x prior to 4.5. It is, therefore, affected by a stored 
cross-site scripting vulnerability due to improper validation of
user-supplied input. An authenticated, remote attacker can exploit
this, via a specially crafted request, to execute arbitrary script
code in a user's browser session.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2015/Jun/att-113/ESA-2015-109.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC Documentum D2 4.5 later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:documentum_d2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
fix_display = FALSE;

if(version =~ "^4\.[1-2]\.")
  fix_display = "4.5.0000 (Any Build)";

if (fix_display)
{
  set_kb_item(name:"www/"+port+"/XSS",value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL           : ' + build_url(port:port, qs:install['path']) +
      '\n  Version       : ' + install['display_version'] +
      '\n  Fixed version : ' + fix_display +
      '\n';

    security_note(extra:report, port:port);
  }
  else security_note(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url, display_version);
