#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96961);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/06 16:27:35 $");

  script_cve_id("CVE-2016-9872", "CVE-2016-9873");
  script_bugtraq_id(95824, 95828);
  script_osvdb_id(151043, 151044);
  script_xref(name:"IAVB", value:"2017-B-0014");

  script_name(english:"EMC Documentum D2 4.5.x and 4.6.x < 4.7 Multiple Vulnerabilities (ESA-2016-167)");
  script_summary(english:"Checks the version of Documentum D2.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of EMC Documentum D2 that is
4.5.x or 4.6.x prior to 4.7. It is, therefore, affected by multiple
vulnerabilities :

  - A cross-site scripting (XSS) vulnerability exists due to
    improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary script
    code in a user's browser session. (CVE-2016-9872)

  - A Document Query Language (DQL) injection vulnerability
    exists due to a failure to properly sanitize
    user-supplied input. An authenticated, remote attacker
    can exploit this to inject or manipulate DQL queries in
    the back-end database, resulting in the manipulation or
    disclosure of arbitrary data. (CVE-2016-9873)");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2017/Jan/att-80/ESA-2016-167.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC Documentum D2 version 4.7 or later. Alternatively, note
that EMC has released 4.5.0200 (4.5 patch 20) and 4.6.0080 (4.6 patch
08) to resolve CVE-2016-9872.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:documentum_d2");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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

if (version =~ "^4\.5\." || version =~ "^4\.6\.")
{
  fix = "4.7.0000";
  fix_display = "4.7.0000 (4.7)";
}

if (!isnull(fix) && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  order  = make_list("URL", "Version", "Fixed version");
  report = make_array(
    order[0], build_url(port:port, qs:install['path']),
    order[1], install['display_version'],
    order[2], fix_display
  );
  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report, xss:TRUE);
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url, display_version);
