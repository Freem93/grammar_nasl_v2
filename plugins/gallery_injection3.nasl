#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12030);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2014/04/23 16:29:27 $");

  script_cve_id("CVE-2004-2124");
  script_bugtraq_id(9490);
  script_osvdb_id(3737);

  script_name(english:"Gallery HTTP Global Variables File Inclusion");
  script_summary(english:"Checks for the presence of init.php");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server is running a PHP application that is affected by
a remote file inclusion vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"It is possible to make the remote host include PHP files hosted on a
third-party server using the version of Gallery installed on the remote
host.

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server."
  );
  script_set_attribute(attribute:"see_also", value:"http://galleryproject.org/node/107");
  script_set_attribute(attribute:"solution", value:"Upgrade to Gallery 1.4.1-pl1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/01/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gallery_project:gallery");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");

  script_dependencies("gallery_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP", "www/gallery");
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
  appname:"gallery",
  port:port,
  exit_on_fail:TRUE
);

dir = install["dir"];

res = http_send_recv3(
  method  : "GET",
  item    : dir+"/init.php?HTTP_PST_VARS[GALLERY_BASEDIR]=http://xxxxxxxx./",
  port    : port,
  exit_on_fail : TRUE
);

if ("http://xxxxxxxx./Version.php" >< res[2]) security_warning(port);
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Gallery", build_url(qs:dir, port:port));
