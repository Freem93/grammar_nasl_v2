#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23934);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2006-6104");
  script_bugtraq_id(21687);
  script_osvdb_id(32391);

  script_name(english:"Mono XSP for ASP.NET Server Crafted Request Script Source Code Disclosure");
  script_summary(english:"Tries to retrieve ASPX source code using XSP");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Mono XSP, a lightweight web server for
hosting ASP.NET applications. 

The version of Mono XSP installed on the remote Windows host fails to
properly validate filename extensions in URLs.  A remote attacker may
be able to leverage this issue to disclose the source of scripts
hosted by the affected application using specially crafted requests
with URL-encoded space characters." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7eb7aad8" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/454962/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e26e3abc" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mono version 1.2.2 / 1.1.13.8.2 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");


 script_set_attribute(attribute:"plugin_publication_date", value: "2006/12/23");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/12/20");
 script_cvs_date("$Date: 2016/05/16 14:12:49 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

banner = get_http_banner(port:port);
if (! banner) exit(1, "No web banner on port "+port);

if ("Server: Mono.WebServer" >!< banner) exit(0, "Mono.webServer is not running on port "+port);

  files = get_kb_list(string("www/", port, "/content/extensions/aspx"));
  if (isnull(files)) files = make_list("/index.aspx", "/Default.aspx");

  n = 0;
  foreach file (files)
  {
    w = http_send_recv3(method:"GEt", item:string(file, "%20"), port:port);
    if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
    res = w[2];

    if (
      "<%@ " >< res && 
      egrep(pattern:"<%@ +language=", string:res, icase:TRUE)
    )
    {
      if (report_verbosity > 1)
        report = string(
          "Here is the source that Nessus was able to retrieve : \n",
          "\n",
          "  ", file, " :\n",
          "\n",
          res
        );
      else report = NULL;
      security_warning(port:port, extra:report); 
      exit(0);
    }
    n++;
    if (n > 20) exit(0);
  }
