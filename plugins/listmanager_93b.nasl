#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31134);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2007-6319");
  script_bugtraq_id(26792);
  script_osvdb_id(42160, 42161, 42162);
  script_xref(name:"Secunia", value:"29019");

  script_name(english:"ListManager < 9.3b / 9.2c / 8.95d Multiple Vulnerabilities");
  script_summary(english:"Checks version in web interface banner");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running ListManager, a web-based commercial mailing
list management application from Lyris. 

According to its banner, the version of ListManager installed on the
remote host relies on client-side code to validate unspecified form
parameters before processing them.  An attacker who is subscribed to a
list managed by the affected application can reportedly leverage this
issue to elevate his privileges to list administrator or gain access
to arbitrary mailing lists. 

In addition, once administrative access has been granted, another
vulnerability in ListManager's administrative interface allows
creation of new accounts that collide with existing accounts, which
results in overwriting data in the those accounts." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Feb/294" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ListManager 9.3b / 9.2c / 8.95d or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(264);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/02/22");
 script_cvs_date("$Date: 2016/10/27 15:03:54 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

# Grab the Server response header.
banner = get_http_banner(port:port);
if (!banner || "Server: " >!< banner)
 exit(1, "Empty web server banner on port "+port);

server = strstr(banner, "Server: ");
server = server - strstr(server, '\r\n');


# If it's for ListManager...
if (
  'Www-Authenticate: Basic realm="Lyris ListManager' >< banner &&
  (
    "Server: ListManagerWeb/" >< server ||
    # earlier versions (eg, 8.5)
    "Server: Tcl-Webserver" >< server
  )
)
{
  vuln = FALSE;
  if ("Server: Tcl-Webserver" >< server) vuln = TRUE;
  else 
  {
    version = strstr(server, "ListManagerWeb/") - "ListManagerWeb/";
    if (" (based on" >< version) version = version - strstr(version, " (based on");
    if (
      version && 
      (
        # I hate ListManager's version numbers!
        version =~ "^[0-7]\." ||
        version =~ "^8\.([0-8]($|[^0-9])|9($|[^5]|5($|[a-c])))" ||
        version =~ "^9\.([01]($|[^0-9])|2($|[ab])|3($|a))"
      )
    ) vuln = TRUE;
  }

  if (vuln)
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "The remote ListManager web interface returned the following Server\n",
        "response header :\n",
        "\n",
        "  ", server, "\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
  }
}
