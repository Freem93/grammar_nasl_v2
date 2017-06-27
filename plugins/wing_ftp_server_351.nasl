#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(47698);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/02 20:50:26 $");

  script_cve_id("CVE-2010-2428");
  script_bugtraq_id(40510);
  script_osvdb_id(65444);

  script_name(english:"Wing FTP Server < 3.5.1 XSS");
  script_summary(english:"Checks version in Wing FTP Server HTTP banner");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a cross-site scripting
vulnerability."
  );
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of Wing
FTP Server earlier than 3.5.1. 

The web server included with such versions is affected by a cross-site
scripting vulnerability.  By sending a specially crafted 'POST'
request to the admin web interface, an authenticated, remote attacker
may be able to leverage this issue to inject arbitrary HTML or script
code into a user's browser to be executed within the security context
of the affected site.");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9d9430a2");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2010/Jun/30");
  script_set_attribute(attribute:"see_also", value:"http://www.wftpserver.com/serverhistory.htm" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wing FTP Server 3.5.1 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/09");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 5466);
  script_require_keys("www/wingftp");
  exit(0);
}

include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

port = get_http_port(default:5466,embedded:TRUE);

banner = get_http_banner(port:port);
if (!banner) exit(1, "Unable to get banner from web server on port "+port+".");
if ("Server:" >!< banner) exit(1, "The banner from the web server on port "+port+" does not have a Server response header.");

server = chomp(egrep(string: banner, pattern: "^Server:"));
if("Wing FTP" >!< server)
  exit(0,"The banner from the web server on port "+ port + " does not appear to be from Wing FTP Server.");

matches = eregmatch(pattern:"Wing FTP Server/([0-9.]+)", string:server);
if(matches)
{
  version = matches[1];
  if(version =~ "^([0-2]\.|3\.[0-4]($|\.)|3\.5(\.0)?$)")
  {
    set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

    if (report_verbosity > 0)
    {
      report = '\n  Installed version  : ' + version +
               '\n  Version source     : ' + server + 
               '\n  Fixed version      : 3.5.1\n';
      security_note(port:port, extra:report);
    }
    else security_note(port:port);
    exit(0);
  }
}
else exit(1, "It was not possible to extract the version of Wing FTP Server listening on port "+ port + " from the banner " + server + ".");
