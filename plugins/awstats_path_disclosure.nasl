#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35975);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/09/24 20:59:28 $");

  script_bugtraq_id(34159);
  script_xref(name:"Secunia", value:"34346");

  script_name(english:"AWStats 'awstats.pl' Path Disclosure");
  script_summary(english:"Tries to read a nonexistent config file");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application which is affected by a
path disclosure issue.");
  script_set_attribute(attribute:"description", value:
"AWStats is installed on the remote system.  AWStats could be installed
as a standalone package or could be bundled or shipped with a
third-party software such as WebGUI Runtime Environment.  The installed
version is affected by a path disclosure vulnerability.  By specifying a
nonexistent config file to the 'config' parameter in awstats.pl, it may
be possible for an attacker to view install path information.");
  script_set_attribute(attribute:"see_also", value:"http://www.plainblack.com/bugs/tracker/8964");
  script_set_attribute(attribute:"solution", value:
"AWStats standalone package        - Unknown at this time.
WebGUI Runtime Environment (WRE)  - Upgrade to WRE 0.9.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:laurent_destailleur:awstats");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("awstats_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/AWStats");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

port = get_http_port(default:80, embedded: 0);

# Test an install.
install = get_install_from_kb(appname:'AWStats', port:port);
if (isnull(install)) exit(0, "The 'www/"+port+"/AWStats' KB item is missing.");
dir = install['dir'];

  magic = string("nessus",rand());

  url = string(dir,'/awstats.pl?config=',magic);

  res = http_send_recv3(method:"GET",port:port, item:url);

  if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

  if(magic &&
     "after searching in path" >< res[2] &&
     "Error: Couldn't open config file" >< res[2])
  {
   if(report_verbosity > 0 )
   {
     report = string (
                '\n',
                'Nessus was able to exploit the flaw using following URL : ', '\n\n',
                 build_url(port:port,qs:url),'\n'
                 );
     security_warning(port:port,extra:report);
    }
    else
     security_warning(port);
  }
