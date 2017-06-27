#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89683);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/06/27 14:13:07 $");

  script_osvdb_id(
    135014,
    135015,
    135016,
    135020,
    135021,
    135022
  );

  script_name(english:"Drupal 7.x < 7.43 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Drupal.");

  script_set_attribute(attribute:"synopsis", value:
"The PHP application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Drupal running on the remote web server is 7.x prior to
7.43. It is, therefore, affected by the following vulnerabilities :

  - A flaw exists in the File module that allows an attacker
    to view, delete, or substitute a link to a file that has
    not yet been submitted or processed by a form. An
    authenticated, remote attacker can exploit this, via
    continuous deletion of temporary files, to block all
    file uploads to a site. (VulnDB 135014)

  - A flaw exists in the XML-RPC system due to a failure to
    limit the number of simultaneous calls being made to the
    same method. A remote attacker can exploit this to
    facilitate brute-force attacks. (VulnDB 135015)

  - A cross-site redirection vulnerability exists due to
    improper validation of unspecified input before
    returning it to the user, which can allow the current
    path to be filled-in with an external URL. A remote
    attacker can exploit this, via a crafted link, to
    redirect a user to a malicious web page of the
    attacker's choosing that targets weaknesses in the
    client-side software or is used for phishing attacks.
    (VulnDB 135016)

  - An unspecified reflected file download flaw exists that
    allows an attacker to trick a user into downloading and
    running a file with arbitrary JSON-encoded content.
    (VulnDB 135020)

  - A flaw exists, related to how the user_save() API is
    utilized, due to assigning improper roles when saving
    user accounts. An authenticated, remote attacker can
    exploit this, via crafted data added to a form or array,
    to gain elevated privileges. (VulnDB 135021)

  - An information disclosure vulnerability exists in the
    'have you forgotten your password' due to displaying the
    username when a valid email address is provided. A
    remote attacker can exploit this to obtain the usernames
    recognized by the system. (VulnDB 135022)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/SA-CORE-2016-001");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/drupal-7.43-release-notes");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 7.43 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("drupal_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/Drupal", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Drupal";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
url = build_url(qs:dir, port:port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (version == "7") audit(AUDIT_VER_NOT_GRANULAR, app, port, version);
if (version !~ "^7\.") audit(AUDIT_WEB_APP_NOT_INST, app + " 7.x", port);

if (version =~ "^7\.([0-9]|[1-3][0-9]|4[0-2])($|[^0-9])")
  security_report_v4(
    port:port,
    severity:SECURITY_HOLE,
    extra:
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.43' +
      '\n'
  );
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, version);
