#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11985);
 script_version ("$Revision: 1.17 $");
 script_bugtraq_id(9400);
 script_osvdb_id(
  3449,
  10312,
  10313,
  10314,
  10315,
  10316,
  10317,
  10318,
  10319,
  10320,
  10321,
  10322,
  10323,
  10324,
  10325,
  10326
 );
 
 script_name(english:"Zope < 2.6.3 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application server that is affected
by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote web server is a version of Zope which is older than version
2.6.3. 

There are multiple security issues in all releases prior to version
2.6.3 or 2.7 BETA4 which can be exploited by an attacker to perform
cross-site scripting attacks, obtain information about the remote
host, or disable this service remotely. 

Note that Nessus solely relied on the version number of the server,
so if the hotfix has already been applied, this might be a false
positive" );
 script_set_attribute(attribute:"see_also", value:"http://mail.zope.org/pipermail/zope-announce/2004-January/001325.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Zope 2.6.3 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/01/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/01/08");
 script_cvs_date("$Date: 2015/02/13 21:07:15 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks Zope version"); 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
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
  if(egrep(pattern:"Server: .*Zope 2\.(([0-5]\..*)|(6\.[0-2][^0-9])|(7\..*BETA *[0-3]))", 
  		string:banner))
  {
     security_warning(port);
     set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
