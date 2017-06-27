#
# (C) Tenable Network Security
#

include("compat.inc");

if (description)
{
  script_id(21223);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2006-1250");
  script_bugtraq_id(17009);
  script_osvdb_id(23877);

  script_name(english:"Winmail Server Webmail Unspecified Vulnerability");
  script_summary(english:"Checks version of Winmail Server");

 script_set_attribute(attribute:"synopsis", value:
"The remote webmail server is affected by an unspecified issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Winmail Server, a commercial mail server
for Windows from AMAX Information Technologies.

According to its version number, the remote installation of Winmail
Server is affected by an unknown issue in its webmail component. It
is unclear whether this is the same issue identified by Secunia in 
November 2005 and covered by Bugtraq ID 15493." );
 script_set_attribute(attribute:"see_also", value:"http://www.magicwinmail.net/changelog.asp" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Winmail Server 4.3(Build 0302) or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/04/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/03/02");
 script_cvs_date("$Date: 2011/03/15 18:34:12 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 6080);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:6080);

# Get the version number from the webmail server's banner.
res = http_get_cache(item:"/", port:port, exit_on_fail: 1);
if (
  "Winmail Server Webmail bases on the UebiMiau." &&
  egrep(pattern:"WebMail \| Powered by Winmail Server ([0-3]\.|4\.[0-2])", string:res)
) security_hole(port);
