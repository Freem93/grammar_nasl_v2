#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76939);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/04/29 20:26:25 $");

  script_cve_id("CVE-2014-1474");
  script_bugtraq_id(68690);
  script_osvdb_id(109314);

  script_name(english:"Request Tracker 4.2.x < 4.2.5 Email::Address:List Module String Handling DoS");
  script_summary(english:"Checks the version of Request Tracker.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a Perl application that is affected
by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Best Practical
Solutions Request Tracker (RT) running on the remote web server is
version 4.2.x prior to 4.2.5. It is, therefore, potentially affected
by a denial of service vulnerability due to an algorithmic complexity
flaw in the Perl CPAN Email::Address:List module. A remote attacker,
by submitting a crafted string without an address, can exploit this
to cause a denial of service through exhaustion of CPU resources.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.bestpractical.com/release-notes/rt/4.2.5");
  # http://blog.bestpractical.com/2014/01/security-vulnerability-in-rt-42.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c21c8430");

  script_set_attribute(attribute:"solution", value:
"Upgrade to Request Tracker 4.2.5 or Email::Address::List 0.02.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/31");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bestpractical:rt");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("rt_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("installed_sw/RT", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

appname = "RT";
get_install_count(app_name:appname, exit_if_zero:TRUE);

port = get_http_port(default:80);
install = get_single_install(app_name:appname, port:port, exit_if_unknown_ver:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

dir = install['path'];
install_url = build_url(port:port, qs:dir + "/");
version = install['version'];

# Versions 4.2.0, 4.2.1, and 4.2.2 are affected
if (version =~ "^4\.2\.[0-2]($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 4.2.5' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, version);
