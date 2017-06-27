#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78392);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/10/14 00:03:54 $");

  script_cve_id("CVE-2014-2544");
  script_bugtraq_id(66763);
  script_osvdb_id(105629);

  script_name(english:"TIBCO Spotfire Server Authentication Module Unspecified Remote Code Execution");
  script_summary(english:"Checks for TIBCO Spotfire Server.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of TIBCO Spotfire Server that is
affected by a remote code execution vulnerability due to a unspecified
flaw in the Authentication Module. A remote attacker can exploit this
vulnerability to execute arbitrary code on the remote host, subject to
the privileges of the account running the affected application.");
  # http://www.tibco.com/assets/bltb7daa51c165cf590/spotfire_advisory_20140409_tcm8-20764.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?584e9c5e");
  # http://www.tibco.com/services/support/advisories/spotfire-advisory_20140409
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3239d8ea");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tibco:spotfire_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");

  script_dependencies("tibco_spotfire_server_detect.nbin");
  script_require_keys("installed_sw/TIBCO Spotfire Server");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:80);

app_name = "TIBCO Spotfire Server";
install = get_single_install(app_name:app_name, port:port, exit_if_unknown_ver:TRUE);

url = build_url(port:port, qs:install['path']);
version = install['version'];

fix = FALSE;

if (version =~ "^4\.5\.")
  fix = "4.5.1";
else if (version =~ "^5\.0\.")
  fix = "5.0.2";
else if (version =~ "^5\.5\.")
  fix = "5.5.1";
else if (version =~ "^6\.0\.")
  fix = "6.0.2";

if (fix && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
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
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url, version);
