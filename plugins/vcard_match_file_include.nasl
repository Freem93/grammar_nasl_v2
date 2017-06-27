#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20133);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2005-3332");
  script_bugtraq_id(15207);
  script_osvdb_id(20699);

  script_name(english:"vCard define.inc.php match Parameter Remote File Inclusion");
  script_summary(english:"Checks for match parameter remote file inclusion vulnerability in vCard");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a remote
file include vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running vCard, a web-based electronic
postcard application from Belchior Foundry and written in PHP. 

The version of vCard installed on the remote host fails to sanitize
the 'match' parameter before using it in the 'admin/define.inc.php'
script to read other files.  By leveraging this flaw, an
unauthenticated attacker may be able to execute script files from
third-party hosts." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Oct/353");
 script_set_attribute(attribute:"solution", value:
"Restrict access to the vCard's 'admin' directory using, say, a
.htaccess file." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/11/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/10/25");
 script_cvs_date("$Date: 2016/11/03 14:16:36 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
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


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/vcard", "/vcards", "/ecard", "/cards", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw to read from a nonexistent host.
  r = http_send_recv3(method:"GET", port: port,
    item:string(
      dir, "/admin/define.inc.php?",
      "match=http://xxxx./" ) );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if we see a PHP error.
  if (
    "Call to a member function on a non-object" >< res &&
    "/admin/define.inc.php" >< res
  ) {
    if (report_verbosity > 0) {
      report = string(
        "\n",
        res
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    exit(0);
  }
}
