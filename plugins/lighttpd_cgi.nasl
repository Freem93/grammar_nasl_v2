#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(16475);
  script_version("$Revision: 1.14 $");
  script_cve_id("CVE-2005-0453");
  script_bugtraq_id(12567);
  script_osvdb_id(13844);
  script_xref(name:"GLSA", value:"200502-21");
 
  script_name(english:"lighttpd < 1.3.8 Null Byte Request CGI Script Source Code Disclosure");
  script_summary(english:"Checks for version of Sami HTTP server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure 
vulnerability." );
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of lighttpd running on the remote
host is prior to 1.3.8. It is, therefore, affected by an information
disclosure vulnerability. An unauthenticated, remote attacker can
exploit this vulnerability, by requesting a CGI script that is
appended by a '%00', to read the source of the script.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://article.gmane.org/gmane.comp.web.lighttpd/1171");
  script_set_attribute(attribute:"solution", value:
"Upgrade to lighttpd version 1.3.8 or later" );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/16");
  script_set_attribute(attribute:"vuln_publication_date", value: "2005/02/12");

  script_cvs_date("$Date: 2016/06/21 19:27:16 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:lighttpd:lighttpd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");
  script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(!get_port_state(port)) exit (0);

banner = get_http_banner(port: port);
if(!banner)exit(0);

if ( egrep(pattern:"^Server: lighttpd/(0\.|1\.([0-2]\.|3\.[0-7][^0-9]))", string:banner) ) 
 {
   security_warning(port);
 }
