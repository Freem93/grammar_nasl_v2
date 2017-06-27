#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(17725);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2014/05/29 04:24:09 $");

  script_cve_id("CVE-2008-5550");
  script_bugtraq_id(32771);
  script_osvdb_id(50971);

  script_name(english:"Sun Java Web Console BeginLogin.jsp redirect_url Parameter URI Redirection");
  script_summary(english:"Checks web console version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server has a URI redirection vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Sun Java Web Console running on the remote host may
have a URI redirection vulnerability.  An attacker could exploit this
by tricking a user into requesting a specially crafted URL, which
would redirect the user to an arbitrary website.  This could result
in further attacks (e.g.  phishing)."
  );
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1019686.1.html");
  script_set_attribute(
    attribute:"solution",
    value:"Apply the relevant patch referenced in Sun Alert 243786."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/12/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sun:java_web_console");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 6788, 6789);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


# Currently don't have a way of telling if some patches are installed remotely.
if (report_paranoia < 2 && !get_kb_item("Settings/PCI_DSS")) exit(1, "This plugin only runs if 'Report paranoia' is set to 'Paranoid'.");

port = get_http_port(default:6789);

# Make sure it's Sun Java Web Console.
banner = http_get_cache(port:port, item: "/", exit_on_fail: 1);

redirect = strstr(banner, "Location:");
if (strlen(redirect)) redirect = redirect - strstr(redirect, '\r\n');
if (strlen(redirect) == 0 || "login/BeginLogin.jsp" >!< redirect)
  exit(0, 'Sun Java Web Console doesn\'t appear to be on port ' + port + '.');

# Try to retrieve the version number.
w = http_send_recv3(method:"GET", item:"/console/html/en/console_version.shtml", port:port, exit_on_fail: 1);
res = w[2];

if (
  "title>Sun Java(TM) Web Console: Version<" >< res &&
  '"VrsHdrTxt">Version ' >< res
)
{
  version = strstr(res, '"VrsHdrTxt">Version ') - '"VrsHdrTxt">Version ';
  if (strlen(version))
    version = version - strstr(version, '</div');
  else
    exit(1, 'Unable to extract version from port ' + port);

  # later versions didn't include the version number directly on the web page
  if ('version.txt' >< version)
  {
    w = http_send_recv3(method:"GET", item:"/console/html/en/version.txt", port:port, exit_on_fail: 1);
    version = w[2];
    if (version !~ '^[0-9.]+$')
      exit(1, 'Error getting version from port ' + port);
  }

  # nb: Sun only talks about 3.0.2, 3.0.3, 3.0.4, and 3.0.5 as affected.
  if (version =~ "^3\.0\.[2-5]($|[^0-9])")
  {
    if (report_verbosity)
    {
      report =
        '\n' +
        'Sun Java Web Console version ' + version + ' is installed on the remote host.\n\n' +
        'It is not possible for Nessus to tell if security patches that fix this\n' +
        'vulnerability on some platforms have been applied.\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
  }
  else exit(0, 'The Sun Java Web Console ' + version + ' install on port ' + port + ' is not affected.');
}
else exit(0, 'Unexpected response received from port ' + port + '.');
