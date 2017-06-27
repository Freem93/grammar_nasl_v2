#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33869);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2015/09/24 21:17:11 $");

  script_cve_id("CVE-2008-3273", "CVE-2010-1429");
  script_bugtraq_id(30540, 39710);
  script_osvdb_id(47551, 64173);
  script_xref(name:"RHSA", value:"2010:0376");
  script_xref(name:"RHSA", value:"2010:0377");
  script_xref(name:"RHSA", value:"2010:0378");
  script_xref(name:"RHSA", value:"2010:0379");
  script_xref(name:"Secunia", value:"39563");

  script_name(english:"JBoss Enterprise Application Platform (EAP) Status Servlet Request Remote Information Disclosure");
  script_summary(english:"Attempts to access status servlet without credentials");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a servlet that is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of JBoss Enterprise Application Platform (EAP) running on
the remote host allows unauthenticated access to a status servlet,
which is used to monitor sessions and requests sent to the server.

This vulnerability (CVE-2008-3273) was fixed in versions 4.2.0.CP03
and 4.3.0.CP01, but was later re-introduced (CVE-2010-1429) by an
unrelated bug fix.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=457757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=585900");
  script_set_attribute(attribute:"solution", value:
"Upgrade to JBoss EAP version 4.2.0.CP09 / 4.3.0.CP08.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_cwe_id(264);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jboss:enterprise_application_platform");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:redhat:jboss_enterprise_application_platform");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8080);

# Check if we are looking at JBoss EAP
banner = get_http_banner(port:port);
if (!banner || "JBoss" >!< banner ) exit(0);


# Try to access the status servlet.
exploit = "/status?full=true";
w = http_send_recv3(method:"GET", item:exploit, port:port);
if (isnull(w)) exit(1, "The web server on port "+port+ "did not answer");
res = w[2];

# If the info looks like it is coming from status servlet ...
if (
  "Status Servlet" 	  >< res &&
  "Processing time"       >< res
)
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "Nessus was able to access the status servlet using the following URL :\n",
      "\n",
      "  ", build_url(port:port, qs:exploit), "\n"
    );
    if (report_verbosity > 1 && "Application list</h1><p>" >< res)
    {
      # Report the application list.
      apps = strstr(res, "Application list</h1><p>") - "Application list</h1><p>";
      if ("</p>" >< apps) apps = apps - strstr(apps, "</p>");
      if (egrep(pattern:"<(h[0-9]|a class)", string:apps)) apps = "";
      else
      {
        apps = str_replace(find:"<br>", replace:'\n  ', string:apps);
        apps = ereg_replace(pattern:"<[^>]+>", replace:"", string:apps);
      }

      if (apps)
      {
        report = string(
          report,
          "\n",
          "Here is the Application list as reported by that servlet :\n",
          "\n",
          "  ", apps, "\n"
        );
       }
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
