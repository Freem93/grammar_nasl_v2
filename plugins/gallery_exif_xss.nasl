#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19512);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/10/10 15:57:05 $");

  script_cve_id("CVE-2005-2734");
  script_bugtraq_id(14668);
  script_osvdb_id(19015);

  script_name(english:"Gallery EXIF Data XSS");
  script_summary(english:"Checks the version of Gallery");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP application that is susceptible to
a cross-site scripting attack."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of Gallery hosted on the remote
web server is prone to script insertion attacks because it does not
sanitize malicious EXIF data stored in image files.  Using a specially
crafted image file, an attacker can exploit this flaw to cause arbitrary
HTML and script code to be executed in a user's browser within the
context of the affected application."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Aug/372");
  script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/project/shownotes.php?release_id=352576");
  # http://galleryproject.org/page/gallery_1_5_pl1_security_release_and_gallery_1_5_1_rc3_preview_release
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f8713d35");
  script_set_attribute(attribute:"solution", value:"Upgrade to Gallery 1.5-pl1 / 1.5.1-RC3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gallery_project:gallery");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("gallery_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/gallery", "www/PHP", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(
  appname:"gallery",
  port:port,
  exit_on_fail:TRUE
);

dir = install["dir"];
version = install["ver"];
install_url = build_url(port:port, qs:dir);

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "Gallery", install_url);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Check the version number.
if (version =~ "^(0\.|1\.([0-4]\.|5\.(0|1-RC[1-2])))")
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 1.5-pl1 / 1.5.1-RC3\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Gallery", install_url, version);
