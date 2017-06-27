#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39330);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2012/02/17 02:28:20 $");
  
  script_bugtraq_id(35217);

  script_name(english:"Sun GlassFish Enterprise < 2.1 Patch 02 Denial of Service");
  script_summary(english:"Checks the Version of Sun GlassFish Enterprise Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a local denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Sun GlassFish Enterprise
Server earlier than 2.1 Patch 02.  Such versions are reportedly
affected by a local denial of service vulnerability in the HTTP Engine
and administration interface.  A local attacker could exploit this
issue to crash the affected service.");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1020443.1.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Sun GlassFish 2.1 Patch 02 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/09");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:glassfish_server");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2009-2012 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 4848);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:4848, embedded: 0);

banner = get_http_banner(port:port);
if (banner && "Sun GlassFish Enterprise Server" >< banner)
{
  server = strstr(banner, "Server:");
  pat = "^Server:.*Sun GlassFish Enterprise Server v([0-9\.]+( Patch[0-9]+)?)";
  ver = NULL;
  matches = egrep(pattern:pat, string:server);
  if (matches)
  {
    foreach match(split(matches, keep:FALSE))
    {
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver))
      {
        ver = ver[1];
        break;
      }
    }
  }

  if (!isnull(ver) && ver =~ "^[01]\.|2\.(0|1($| Patch01$))")
  {
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "According to its banner, Sun GlassFish version ", ver, " is installed on the\n",
        "remote host.\n"
      );
      security_note(port:port, extra:report);
    }
    else security_note(port:port);
  }
}
