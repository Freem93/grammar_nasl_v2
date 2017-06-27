#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20926);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2006-0756");
  script_osvdb_id(23207, 23208);

  script_name(english:"dotProject docs/ Directory Multiple Script Information Disclosure");
  script_summary(english:"Checks for docs directory information disclosure vulnerabilities in dotProject");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple information disclosure vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running dotProject, a web-based, open source,
project management application written in PHP. 

The installed version of dotProject discloses sensitive information
because it lets an unauthenticated attacker call scripts in the 'docs'
directory." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/424957/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.dotproject.net/vbulletin/showthread.php?t=4462" );
 script_set_attribute(attribute:"solution", value:
"Remove the application's 'doc' directory." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/02/15");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/02/14");
 script_cvs_date("$Date: 2013/01/25 01:19:07 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:dotproject:dotproject");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0, php: 1);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/dotproject", "/dotProject", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Grab index.php.
  res = http_get_cache(item:string(dir, "/index.php"), port:port, exit_on_fail: 1);

  # It's dotProject if...
  if (
    # it looks like dotProject's index.php or...
    ' alt="dotProject logo"' >< res ||
    # it hasn't been installed yet.
    (
      "<meta http-equiv='refresh' content='5;" >< res &&
      "Click Here To Start Installation and Create One!" >< res
    )
  ) {
    # Try to run the application's phpinfo.php script.
    r = http_send_recv3(method: "GET", item:string(dir, "/docs/phpinfo.php"), port:port, exit_on_fail: 1);

    # There's a problem if it looks like the output of phpinfo().
    if ("PHP Version" >< r[2]) {
      security_warning(port);
      exit(0);
    }
  }
}
