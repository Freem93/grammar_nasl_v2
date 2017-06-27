#
# (C) Tenable Network Security, Inc.
#

#
# Thanks to Joel R Helgeson of SECURE ITnet, Inc. for suggesting this 
# plugin and helping with its development.
#


include("compat.inc");


if (description)
{
  script_id(42210);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/09/24 23:21:21 $");

  script_name(english:"Trapeze Service Shell - Admin Service Accessible");
  script_summary(english:"Tries to access Trapeze Service Shell's Admin Service");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The administrative console for the remote web server has not been
secured."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote web server is a Trapeze Service Shell, the application
server component included with various products from Trapeze Software,
Inc., such as their traveller information systems for providing public
bus and train route information. 

The remote Trapeze Service Shell has not been securely configured as
it allows uncredentialed access the Admin Service, one of the web
services it provides. 

A remote attacker can leverage this issue to discover sensitive
information about the remote installation of Trapeze or load / unload
Trapeze plugins available on the affected system

Note that there are likely to be other services available through the
affected application that also have not been secured; services which
could expose the application's database or the host's files, although
Nessus has not checked for them."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Apply the proper Security Settings for the Trapeze Service Shell as
discussed in the product's Setup Guide."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/10/22"
  );
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded:FALSE);


# Unless we're being paranoid, make sure the banner looks like Trapeze.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (banner && "Server: Trapeze-Srv/" >!< banner) exit(0, "Server response header for port "+port+" is not from Trapeze.");
}


url = "/Admin";
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail: 1);

if (
  "TITLE>Admin Service - Shell" >< res[2] &&
  "<a href='?Method=ShowShellInfo'>Shell<a>" >< res[2]
)
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "Nessus was able to access the Admin Service using the following URL :\n",
      "\n",
      "  ", build_url(port:port, qs:url), "\n"
    );
    if (report_verbosity > 1)
    {
      # Collect some info for the report.
      vars = make_list(
        "Profile", 
        "InstanceName",
        "ComputerName",
        "FileRoot",
        "DefaultService"
      );

      info = "";
      foreach repinfo (vars)
      {
        element = string("<td>", repinfo, "</td>");
        if (element >< res[2])
        {
          val = strstr(res[2], element) - element;
          val = val - strstr(val, "</tr>");
          val = strstr(val, "<td>") - "<td>";
          val = val - strstr(val, "</td>");
          if (val == "&nbsp;") val = "n/a";
          info += '  ' + repinfo + crap(data:' ', length:20-strlen(repinfo)) + ' : ' + val + '\n';
        }
      }
      report = string(
        "\n",
        "Here is some information Nessus was able to gather about the Trapeze\n",
        "installation :\n",
        "\n",
        info
      );
    }
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
