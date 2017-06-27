#
# Original script written by Tenable Network Security
# Modified by Scott Shebby scotts@scanalert.com
# OS check by George Theall

# Changes by Tenable:
# - Standardized title (4/2/2009)


include("compat.inc");

if(description)
{
 script_id(12280);
 script_version("$Revision: 1.24 $");
 script_cve_id("CVE-2004-0174");
 script_bugtraq_id(9921);
 script_xref(name:"OSVDB", value:"4383");

 script_name(english:"Apache < 1.3.31 / 2.0.49 Socket Connection Blocking Race Condition DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote web server appears to be running a version of Apache that
is prior to 1.3.31 / 2.0.49. It is therefore, affected by a denial of
service vulnerability. A remote attacker can block new connections to
the server by connecting to a listening socket on a rarely accessed
port.

Note that this issue is known to affect some versions of AIX, Solaris,
and Tru64 and known to not affect FreeBSD or Linux." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Mar/191" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Apache 2.0.49 or 1.3.31 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/06/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/03/20");
 script_cvs_date("$Date: 2016/10/07 13:30:46 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:apache:http_server");
script_end_attributes();


 summary["english"] = "Checks for version of Apache";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2016 Scott Shebby");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 if ( ! defined_func("bn_random") )
	script_dependencie("http_version.nasl", "os_fingerprint.nasl");
 else
 	script_dependencie("http_version.nasl", "os_fingerprint.nasl", "macosx_SecUpd20040503.nasl", "macosx_SecUpd20040126.nasl", "macosx_SecUpd20041202.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("backport.inc");

if ( get_kb_item("CVE-2004-0174") ) exit(0);

port = get_http_port(default:80);
if(!port) exit(0);
if(!get_port_state(port))exit(0);

# nb: don't bother checking if platform is known to be unaffected. (george theall)
os = get_kb_item("Host/OS");
if (os && ereg(pattern:"FreeBSD|Linux", string:os, icase:TRUE)) exit(0);


banner = get_backport_banner(banner:get_http_banner(port: port));
if(!banner)exit(0);

serv = strstr(banner, "Server");
if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/2\.0\.([0-9][^0-9]|[0-3][0-9]|4[0-8])", string:serv))
 {
   security_warning(port);
   exit(0);
 }
if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/(1\.([0-2]\.|3\.([0-9][^0-9]|[0-2][0-9]|30)))", string:serv))
 {
   security_warning(port);
   exit(0);
 }
