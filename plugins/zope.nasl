#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10447);
 script_version ("$Revision: 1.24 $");
 script_cve_id("CVE-2000-0483");
 script_bugtraq_id(1354);
 script_osvdb_id(347);
 
 script_name(english:"Zope < 2.1.7 DocumentTemplate Unauthorized DTML Entity Modification");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application server that fails to
protect stored content and code from modification by remote users." );
 script_set_attribute(attribute:"description", value:
"The remote web server is Zope < 2.1.7.  There is a security problem in
these versions that can allow the contents of DTMLDocuments or
DTMLMethods to be changed without forcing proper user authentication." );
 script_set_attribute(attribute:"see_also", value:"http://mail.zope.org/pipermail/zope/2000-June/111952.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.zope.org/Products/Zope/Hotfix_06_16_2000/security_alert" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Zope 2.1.7 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/06/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/06/15");
 script_cvs_date("$Date: 2011/03/17 16:19:57 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks for Zope");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2011 Tenable Network Security, Inc.");
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
if(egrep(pattern:"^Server: .*Zope 2\.((0\..*)|(1\.[0-6]))", string:banner))
     security_hole(port);
}
