#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63065);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/06/10 20:49:25 $");

  script_cve_id(
    "CVE-2012-4730",
    "CVE-2012-4731",
    "CVE-2012-4732",
    "CVE-2012-4734",
    "CVE-2012-4884",
    "CVE-2012-6578",
    "CVE-2012-6579",
    "CVE-2012-6580",
    "CVE-2012-6581"
  );
  script_bugtraq_id(56290, 56291);
  script_osvdb_id(
    86707,
    86708,
    86709,
    86710,
    86711,
    86712,
    86713,
    86714,
    86715
  );

  script_name(english:"Request Tracker 3.x < 3.8.15 / 4.x < 4.0.8 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Request Tracker.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a Perl application that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Best Practical
Solutions Request Tracker (RT) running on the remote web server is
version 3.x prior to 3.8.15 or version 4.x prior to 4.0.8. It is,
therefore, potentially affected by the following vulnerabilities :

  - Users can inject arbitrary headers into outgoing email
    provided they have ModifySelf or AdminUser privileges.
    A remote attacker could exploit this to gain sensitive
    information or conduct phishing attacks. (CVE-2012-4730)

  - Any privileged user can create articles in any class due
    to the application failing to properly verify user
    access rights. (CVE-2012-4731)

  - A cross-site request forgery vulnerability exists that
    allows a remote attacker to hijack the authentication
    of users for requests that toggle ticket bookmarks.
    (CVE-2012-4732)

  - A warning bypass vulnerability exists that allows a
    'confused deputy' attack during the handling of a
    specially crafted link. (CVE-2012-4734)

  - A vulnerability exists that allows an attacker to send
    arbitrary arguments to the command line for the GnuPG
    client (if GnuPG is enabled), which could result in the
    creation of arbitrary files with the permissions of the
    web server. (CVE-2012-4884)

  - Multiple vulnerabilities exist related to the improper
    signing or encryption of messages using GnuPG when GnuPG
    is enabled. (CVE-2012-6578, CVE-2012-6579,
    CVE-2012-6580, CVE-2012-6581)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://blog.bestpractical.com/2012/10/security-vulnerabilities-in-rt.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2181f5d2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Request Tracker 3.8.15 / 4.0.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bestpractical:rt");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

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

app = 'RT';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

path    = install["path"];
version = install["version"];
install_loc = build_url(port:port, qs:path + "/");

ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

# Versions 3.8.x / 4.0.x less than 3.8.15 / 4.0.8 are affected.
if
(
  ver[0] == 3 && ver[1] == 8 &&
  (
    (ver[2] < 15) ||
    (ver[2] == 15 && version =~ "(rc|pre|alpha|RC|test|CH|beta|preflight)")
  )
  ||
  (
    ver[0] == 4 && ver[1] == 0 &&
    (
      (ver[2] < 8) ||
      (ver[2] == 8 && version =~ "(rc|pre|alpha|RC|test|CH|beta|preflight)")
    )
  )
)  
{
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_loc+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 3.8.15 / 4.0.8\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);
