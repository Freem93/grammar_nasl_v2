#
# (C) Tenable Network Security, Inc.
#

# nb: SecurityFocus maps this to CVE-2000-0062, but that refers to
#     an earlier flaw, announced by Christopher Petrilli:
#     http://mail.zope.org/pipermail/zope/2000-January/100903.html


include("compat.inc");

if(description)
{
 script_id(10569);
 script_version ("$Revision: 1.26 $");
 script_cve_id("CVE-2000-1212");
 script_bugtraq_id(922);
 script_osvdb_id(468, 6283);

 script_name(english:"Zope Image and File Update Data Protection Bypass");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application server that fails to
protect stored content from modification by remote users." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote web server is Zope < 2.2.5.  Such
versions suffer from a security issue involving incorrect protection
of a data updating method on Image and File objects.  Because the
method is not correctly protected, it is possible for users with DTML
editing privileges to update the raw data of a File or Image object
via DTML though they do not have editing privileges on the objects
themselves. 

*** Since Nessus solely relied on the version number of the server, 
*** consider this a false positive if the hotfix has already been applied." );
 script_set_attribute(attribute:"see_also", value:"http://mail.zope.org/pipermail/zope-announce/2000-December/000323.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.zope.org/Products/Zope/Hotfix_2000-12-18/security_alert" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Zope 2.2.5 or apply the hotfix referenced in the vendor
advisory above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/12/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/12/12");
 script_cvs_date("$Date: 2014/05/21 17:15:44 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks for Zope");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2014 Tenable Network Security, Inc.");
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
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);

if(banner)
{
  if(egrep(pattern:"Server: .*Zope 2\.((0\..*)|(1\..*)|(2\.[0-4]))", 
  		string:banner))
     security_warning(port);
}

