#
# This script was written by Georges Dagousset <georges.dagousset@alert4web.com>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Updated to use compat.inc (11/16/09)
# - Revised plugin title, OSVDB ref (9/23/09)


include("compat.inc");

if(description)
{
 script_id(10777);
 script_version ("$Revision: 1.22 $");
 script_cvs_date("$Date: 2013/01/25 01:19:11 $");
 script_cve_id("CVE-2001-0567");
 script_osvdb_id(648);
 
 script_name(english:"Zope < 2.3.3 ZClass Permission Mapping Modification Local Privilege Escalation");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application server that is prone
to a privilege escalation flaw." );
 script_set_attribute(attribute:"description", value:
"The remote web server uses a version of Zope which is older than
version 2.3.3.  In such versions, any user can visit a ZClass
declaration and change the ZClass permission mappings for methods and
other objects defined within the ZClass, possibly allowing for
unauthorized access within the Zope instance. 

*** Nessus solely relied on the version number of the server, so if 
*** the hotfix has already been applied, this might be a false positive" );
 script_set_attribute(attribute:"see_also", value:"http://www.zope.org/Products/Zope/Hotfix_2001-05-01/security_alert" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Zope 2.3.3 or apply the hotfix referenced in the vendor
advisory above." );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/09/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/05/01");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks Zope version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2013 Alert4Web.com");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/zope");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");


port = get_http_port(default:80);

banner = get_http_banner(port:port);

if(banner)
{
  if(egrep(pattern:"Server: .*Zope 2\.((0\..*)|(1\..*)|(2\..*)|(3\.[0-2]))", 
  		string:banner))
     security_warning(port);
}
