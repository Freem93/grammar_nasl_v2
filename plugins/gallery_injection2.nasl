#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(11876);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2013/04/02 13:59:06 $");

  script_cve_id("CVE-2003-1227");
  script_bugtraq_id(8814);
  script_osvdb_id(2662);

  script_name(english:"Gallery index.php GALLERY_BASEDIR Parameter Remote File Inclusion");
  script_summary(english:"Checks for the presence of 'setup/index.php'");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server is running a PHP application that is affected by
a remote file inclusion vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Gallery hosted on the remote web server is affected by a
remote file inclusion vulnerability due to the application failing to
properly sanitize user-supplied input to the 'GALLERY_BASEDIR' parameter
of the 'index.php' script.  An attacker may use this flaw to inject
arbitrary code in the remote host and gain a shell with the privileges
of the web server user."
  );
  script_set_attribute(attribute:"see_also", value:"http://galleryproject.org/node/93");
  script_set_attribute(attribute:"solution", value:"Upgrade to Gallery 1.4-pl2 or 1.4.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2003/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/10/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gallery_project:gallery");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2003-2013 Tenable Network Security, Inc.");

  script_dependencie("gallery_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/gallery", "www/PHP");
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

r = http_send_recv3(
  method : "GET",
  item   : dir + "/setup/index.php?GALLERY_BASEDIR=http://xxxxxxxx/",
  port   : port,
  exit_on_fail : TRUE
);

if (egrep(pattern:"http://xxxxxxxx//?util.php", string:r[2])) security_hole(port);
else audit(AUDIT_WEB_APP_NOT_AFFECTED,"Gallery", build_url(qs:dir,port:port));
