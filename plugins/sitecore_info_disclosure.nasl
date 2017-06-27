#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36018);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2009-1055");
  script_bugtraq_id(34162);
  script_osvdb_id(52777);
  
  script_name(english:"Sitecore CMS < 5.3.2 rev. 090212 Web Service Security Database Information Disclosure");
  script_summary(english:"Checks the version number of Sitecore");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by an
information disclosure vulnerability." );
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Sitecore CMS which is
reportedly affected by an information disclosure vulnerability. An
attacker could exploit this in order to gain unauthorized access to
security databases." );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5b86f32e" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Sitecore 5.3.2 (rev. 090212) or newer." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2009/03/26");
 script_cvs_date("$Date: 2016/05/13 15:33:30 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

port = get_http_port(default:80, embedded: 0);

dir = "/sitecore/login";
  
url = string(dir, "/Default.aspx");
w = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail: 1);
res = strcat(w[1], w[2]);

if (
  '<div id="LoginTitle">Welcome to Sitecore' >< res &&
  'Sitecore.NET' >< res
)
{
  pat = 'Sitecore.NET ([0-9.]+) \\(rev\\. ([0-9]+)\\)';
  matches = egrep(pattern:pat, string:res);
  if (matches)
  {
    foreach match (split(matches, keep:FALSE))
    {
      item = eregmatch(pattern:pat, string:match);
      if (!isnull(item))
      {
        version = item[1];
        revision = item[2];

        rev = int(revision);

        if(
          version =~ "^[0-4]\." ||
          version =~ "^5\.[0-2]\." ||
          version =~ "^5\.3\.[0-1]$" ||
          (
            version =~ "^5\.3\.2$" && rev<90212
          )
        )
        {
          if(report_verbosity)
          {
            report = string(
              "\n",
              "Version : ", version, "\n",
              "URL     : ", build_url(port:port, qs:url), "\n"
            );
            security_warning(port:port, extra:report);
          }
          else security_warning(port);
        }
      }
    }
  }
}
