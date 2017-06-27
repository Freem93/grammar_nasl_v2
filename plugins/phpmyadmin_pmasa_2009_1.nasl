#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(36083);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/16 14:22:06 $");

  script_bugtraq_id(34253);
  script_osvdb_id(53226, 53227);
  script_xref(name:"Secunia", value:"34468");

  script_name(english:"phpMyAdmin file_path Parameter Vulnerabilities (PMASA-2009-1)");
  script_summary(english:"Calls bs_disp_as_mime_type.php with a bogus URL");

  script_set_attribute( attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by
multiple issues."  );
  script_set_attribute( attribute:"description",  value:
"The version of phpMyAdmin installed on the remote host fails to
sanitize user-supplied input to the 'file_path' parameter of the
'bs_disp_as_mime_type.php' script before using it to read a file and
reporting it in dynamically-generated HTML.  An unauthenticated, remote
attacker may be able to leverage this issue to read arbitrary files,
possibly from third-party hosts, or to inject arbitrary HTTP headers
in responses sent to third-party users.

Note that the application is also reportedly affected by several other
issues, although Nessus has not actually checked for them."  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2009-1.php"
  );
  script_set_attribute( attribute:"solution",  value:
"Upgrade to phpMyAdmin 3.1.3.1 or apply the patch referenced in the
project's advisory."  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value: "2009/04/03");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/phpMyAdmin", "www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded:FALSE, php:TRUE);


# Test an install.
install = get_kb_item(string("www/", port, "/phpMyAdmin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  basename = SCRIPT_NAME;
  exploit_url = build_url(port:port, qs:dir+"/"+basename);

  url = string(
    dir, "/bs_disp_as_mime_type.php?",
    "file_path=", exploit_url, "&",
    "c_type=1"
  );

  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  # There's a problem if...
  if (
    # we see a header line with our file or ...
    string("attachment; filename=", basename) >< res[1] ||
    # we see an error indicating get_headers() failed (eg, connection failed).
    string("get_headers(", exploit_url, ")") >< res[2]
  )
  {
    security_warning(port);
  }
}
