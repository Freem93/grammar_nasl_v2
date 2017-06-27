#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35619);
  script_version("$Revision: 1.8 $");

  script_bugtraq_id(33585);
  script_xref(name:"EDB-ID", value:"7966");
  script_xref(name:"Secunia", value:"33766");

  script_name(english:"NaviCOPA < 3.01 6th February 2009 Multiple Vulnerabilities");
  script_summary(english:"Check version in banner");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of the NaviCOPA web server
software running on the remote host is either earlier than 3.01 or
3.01 from before the 6th of February 2009.  Such versions are affected
by two vulnerabilities :

  - There is a heap-based buffer overflow that can be
    triggered when handling an overly long GET request.

  - The server returns the source of scripts hosted on it if
    the URL ends in a dot ('.')." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/500626/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to NaviCOPA 3.01 from 6th February 2009 or later as that
reportedly resolves the issues." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/02/09");
 script_cvs_date("$Date: 2011/03/17 16:19:56 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!get_port_state(port)) exit(0);


# Check the version in the banner.
banner = get_http_banner(port:port);
if (!banner) exit(0);

banner = strstr(banner, "Server:");
banner = banner - strstr(banner, '\r\n');
if ("InterVations NaviCOPA Version " >< banner)
{
  version = strstr(banner, "InterVations NaviCOPA Version ") - "InterVations NaviCOPA Version ";
  if (" Trial Version" >< version) version = version - strstr(version, " Trial Version");

  if (
    version =~ "^1\.([0-2]|3\.00)($|[^0-9])" ||
    version =~ "^3\.01 .+ 200[0-8]($|[^0-9])"
  )
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "NaviCOPA version ", version, " is running on the remote host\n",
        "based on the following Server response header :\n",
        "\n",
        "  ", banner, "\n"
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
  }
}
