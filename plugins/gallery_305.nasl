#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65767);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/03 17:40:02 $");

  script_bugtraq_id(58172);
  script_osvdb_id(90590, 90599, 90600, 90601);

  script_name(english:"Gallery < 3.0.5 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Gallery");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version number, the Gallery install hosted on the
remote web server is affected by multiple vulnerabilities :

  - The application is affected by a cross-site scripting
    (XSS) vulnerability because it fails to properly
    sanitize user-supplied input to the 'Module Name' field
    in the advanced settings.  Administrator credentials
    are required in order to exploit this issue.

  - An attacker can delete arbitrary files on the remote
    host under certain conditions when the 'Watermark'
    module is activated.  After a watermark image file has
    been uploaded, the name of the image can be altered in
    the advanced settings section.  This altered name is
    used when deleting the file and can allow an arbitrary
    file to be deleted.  Successful exploitation does
    require administrator credentials.

  - The application is affected by a remote code execution
    vulnerability when the application has not been fully
    installed.  During the application setup, a user enters
    database information in which the 'host', 'username',
    and 'password' fields are not properly sanitized.  An
    unauthenticated, remote attacker can take advantage of
    this vulnerability by using specially crafted input in
    the affected fields in order to execute arbitrary code
    on the remote host.

  - The application is reportedly affected by additional
    cross-site scripting issue related to the version of
    Flowplayer in use by Gallery.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number."
  );
  # http://websec.wordpress.com/2013/03/06/gallery-project-3-0-4-bugbounty-remote-code-execution-admin/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a0631c5e");
  script_set_attribute(attribute:"see_also", value:"http://galleryproject.org/gallery_3_0_5");
  script_set_attribute(attribute:"solution", value:"Upgrade to Gallery 3.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gallery_project:gallery");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("gallery_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP", "www/gallery", "Settings/ParanoidReport");
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
  appname      : "gallery",
  port         : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
install_url = build_url(port:port, qs:dir);
version = install["ver"];

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "Gallery", install_url);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Versions 3.0.x < 3.0.5 are vulnerable
if (ver[0] == 3 && ver[1] == 0 && ver[2] < 5)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 3.0.5\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Gallery", install_url, version);
