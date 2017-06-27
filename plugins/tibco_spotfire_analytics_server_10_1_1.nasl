#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78390);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/02/13 21:07:14 $");

  script_cve_id("CVE-2011-3132", "CVE-2011-3133", "CVE-2011-3134");
  script_bugtraq_id(49404);
  script_osvdb_id(74848, 74849, 74850);

  script_name(english:"TIBCO Spotfire Analytics Server Web Application Multiple Vulnerabilities");
  script_summary(english:"Checks for TIBCO Spotfire Analytics Server.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of TIBCO Spotfire Analytics
Server that is affected by multiple vulnerabilities :

  - A cross-site scripting vulnerability exists that allows
    a remote attacker to view or modify sensitive
    information. (CVE-2011-3132)

  - A session fixation vulnerability exists that allows a
    remote attacker to hijack another user's session.
    (CVE-2011-3133)

  - A SQL injection flaw exists that allows a remote
    attacker to view and modify sensitive information by
    sending a sending a specially crafted URL.
    (CVE-2011-3134)");
  # http://www.tibco.com/assets/bltc5c4416bb3129a5a/spotfire_advisory_20110831_tcm8-14230.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?06c9b20a");
  # http://www.tibco.com/services/support/advisories/spotfire-advisory_20110831
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87e0916c");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tibco:spotfire_analytics_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");

  script_dependencies("tibco_spotfire_server_detect.nbin");
  script_require_keys("installed_sw/TIBCO Spotfire Analytics Server");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:80);

app = "TIBCO Spotfire Analytics Server";;
install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);

url = build_url(port:port, qs:install['path']);
version = install['version'];

fix = "10.1.1";

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';

    security_hole(extra:report, port:port);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, version);
