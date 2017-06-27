#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
# www.westpoint.ltd.uk
#
# June 4, 2002 Revision 1.9 Additional information and refrence information
# added by Michael Scheidell SECNAP Network Security, LLC June 4, 2002
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title (4/7/2009)
# - Description touch-up, tighten check (3/28/2011)

include("compat.inc");

if (description)
{
 script_id(10767);
 script_version("$Revision: 1.29 $");
 script_cvs_date("$Date: 2013/11/04 02:28:18 $");

 script_xref(name:"MSFT", value:"MS01-044");
 script_xref(name:"CERT-CC", value:"CA-2001-26");

 script_name(english:"Nimda Worm Infected HTML File Detection");
 script_summary(english:"Tests for Nimda Worm infected HTML files");

 script_set_attribute(attribute:"synopsis", value:"The remote host may have been compromised.");
 script_set_attribute(attribute:"description", value:
"The remote web server appears to have been compromised by the Nimda
mass mailing worm.  It uses various known IIS vulnerabilities to
compromise the server.

Visitors to such a compromised web server may be prompted to download an
.eml (Outlook Express) email file, which contains the worm as an
attachment.

In addition, the worm will create open network shares on the infected
computer, allowing access to the system.  During this process the worm
creates the guest account with Administrator privileges.

Note that this plugin only looks for the presence of the string injected
by the Nimda worm on the remote web server and may result in false
positives.");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms01-044");
 script_set_attribute(attribute:"solution", value:
"Take this server offline immediately, rebuild it and apply ALL vendor
patches and security updates before reconnecting it to the Internet, as
well as security settings discussed in the Additional Information
section of MS01-044.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value:"2001/09/19");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001-2013 Matt Moore");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check for references to readme.eml in default HTML page..

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (get_port_state(port))
{
 r = http_get_cache(item:"/", port:port);
 if (
  r &&
  "readme.eml" >< r &&
  '<script language="JavaScript">' >< r &&
  egrep(pattern:'window\\.open\\("readme\\.eml", *null', string:r)
 ) security_hole(port);
}
