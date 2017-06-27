#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14338);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/10/10 15:57:05 $");

  script_cve_id("CVE-2004-1466");
  script_bugtraq_id(10968);
  script_osvdb_id(9019);

  script_name(english:"Gallery save_photos.php Arbitrary Command Execution");
  script_summary(english:"Checks for the version of Gallery");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP application that is affected by a
remote command execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Gallery hosted on the remote web server is affected by
an arbitrary command execution vulnerability.  This could allow an
attacker to execute arbitrary commands on the remote host by uploading a
file containing arbitrary PHP code.  When the temp directory is web
accessible, the attacker has a 30 second window to access the script and
execute the remote code before the file is deleted. 

Note that in order to exploit this flaw, an attacker would require the
privileges to upload files to a remote photo album."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2004/Aug/803");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2004/Aug/960");
  script_set_attribute(attribute:"see_also", value:"http://galleryproject.org/node/134");
  script_set_attribute(attribute:"solution", value:"Upgrade to Gallery 1.4.4-pl1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gallery_project:gallery");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

  script_dependencie("gallery_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/gallery", "www/PHP", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(
  appname      : "gallery",
  port         : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
version = install["ver"];
install_url = build_url(port:port, qs:dir);

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "Gallery", install_url);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Versions < 1.4.4-pl1 are affected
if (
  version =~ "^0\." ||
  version =~ "^1\.([0-3]|4\.([0-3]|4|4-pl0))([^0-9]|$)"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 1.4.4-pl1\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Gallery", install_url, version);
