#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21019);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/10/10 15:57:05 $");

  script_cve_id("CVE-2005-4021");
  script_bugtraq_id(15614);
  script_osvdb_id(21311);

  script_name(english:"Gallery Install Log Local Information Disclosure");
  script_summary(english:"Checks for Gallery install log");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP application that is prone to an
information disclosure issue."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installation of Gallery hosted on the remote web server places its
data directory under the web server's document root and makes its
install log available to anyone.  Using a simple GET request, a remote
attacker can retrieve this log and discover sensitive information about
the affected application and host, including installation paths, the
admin password hash, etc. 

The install is reportedly also affected by a cross-site scripting
vulnerability in the 'Add Image From Web' feature as well as an
information disclosure issue with the ZipCart module, although Nessus
has not tested for these additional issues."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Nov/366");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/418200");
  script_set_attribute(attribute:"see_also", value:"http://galleryproject.org/gallery_2.0.2_released");
  script_set_attribute(
    attribute:"solution",
    value:
"Move the gallery data directory outside the web server's document
root, remove the file 'install.log' in that directory, or upgrade to
version 2.0.2 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/03/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gallery_project:gallery");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("gallery_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/gallery", "www/PHP");
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

res = http_send_recv3(
  method : "GET",
  item   : dir + "/g2data/install.log",
  port   : port,
  exit_on_fail : TRUE
);

# There's a problem if it looks like the install log.
if ("Prepare installation of the core module" >< res[2])
{
  if (report_verbosity > 1)
  {
    report = "\n" + res[2];
    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Gallery", build_url(qs:dir, port:port));
