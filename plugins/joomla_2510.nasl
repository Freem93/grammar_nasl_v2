#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66389);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/05/19 13:58:06 $");

  script_cve_id(
    "CVE-2013-3056",
    "CVE-2013-3057",
    "CVE-2013-3058",
    "CVE-2013-3059",
    "CVE-2013-3242",
    "CVE-2013-3267"
  );
  script_bugtraq_id(
    59483,
    59484,
    59485,
    59486,
    59487,
    59489,
    59490
  );
  script_osvdb_id(
    92750,
    92751,
    92752,
    92753,
    92754,
    92755,
    92756
  );
  script_xref(name:"EDB-ID", value:"25087");

  script_name(english:"Joomla! 2.5.x < 2.5.10 / 3.0.x < 3.0.4 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Joomla!.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-identified version number, the Joomla!
installation hosted on the remote web server is 2.5.x prior to 2.5.10
or 3.0.x prior to 3.0.4. It is, therefore, affected by multiple
vulnerabilities :

  - A security bypass vulnerability exists due to a failure
    to properly verify permissions before deleting private
    messages. An authenticated, remote attacker can
    exploit this to delete arbitrary private messages.
    (CVE-2013-3056)

  - An information disclosure vulnerability exists due to
    improper verification of permissions when viewing
    permission settings. An authenticated, remote attacker
    can exploit this to disclose restricted permission
    settings. (CVE-2013-3057)

  - An unspecified cross-site scripting (XSS) vulnerability
    exists due to improper validation of user-supplied
    input. An unauthenticated, remote attacker can exploit
    this, via a specially crafted request, to execute
    arbitrary script code in a user's browser session.
    (CVE-2013-3058)

  - A cross-site scripting vulnerability (XSS) exists in the
    Voting plugin due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this, via a specially crafted request, to
    execute arbitrary script code in a user's browser
    session. (CVE-2013-3059)

  - A flaw exists in the remember.php script due to
    improper sanitization of input passed via a cookie
    parameter before being used in an unserialize() call.
    An authenticated, remote attacker can exploit this
    to unserialize arbitrary PHP objects, resulting in a
    denial of service condition or a PHP object injection
    attack. (CVE-2013-3242)

  - A cross-site scripting (XSS) vulnerability exists in the
    Highlighter plugin due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this, via a specially crafted request, to
    execute arbitrary script code in a user's browser
    session. (CVE-2013-3267)

  - A cross-site scripting (XSS) vulnerability exists in the
    Flash-Based File Uploader due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this, via a specially crafted request, to
    execute arbitrary script code in a user's browser
    session. (VulnDB 92751)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.joomla.org/announcements/release-news/5493-joomla-2-5-10-released.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?93cf315a");
  # https://www.joomla.org/announcements/release-news/5494-joomla-3-1-0-stable-released.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c07561c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 2.5.10 / 3.0.4 / 3.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Joomla!", "www/PHP", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Joomla!";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

version = install['version'];
install_loc =  build_url(port:port, qs:install['path']);

fix = "2.5.10 / 3.0.4 / 3.1.0";

# Check granularity
if (version =~ "^2(\.5)?$" || version =~ "^3(\.0)?$")
  audit(AUDIT_VER_NOT_GRANULAR, app, port, version);


# Versions 2.5.x < 2.5.10 and 3.0.x < 3.0.4 are vulnerable
if (
  version =~ "^2\.5\.[0-9]($|[^0-9])" ||
  version =~ "^3\.0\.[0-3]($|[^0-9])"
)
{
  order = make_list("URL", "Installed version", "Fixed version");
  report = make_array(
    order[0], install_loc,
    order[1], version,
    order[2], fix
  );
  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING, xss:TRUE);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);
