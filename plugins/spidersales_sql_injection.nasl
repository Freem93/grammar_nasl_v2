#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(12088);
  script_cve_id("CVE-2004-0348");
  script_bugtraq_id(9799);
  script_osvdb_id(4141);
  script_version ("$Revision: 1.13 $");

  script_name(english:"SpiderSales Shopping Cart SQL injection");
  script_summary(english:"Checks for the presence of SpiderSales Shopping cart");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote web application is vulnerable to an injection attack.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The remote host is running the SpiderSales Shopping Cart CGI suite.

There is a bug in this suite which may allow an attacker
to force it to execute arbitrary SQL statements on the remote
host. An attacker may use this flaw to gain the control of the remote
website and possibly execute arbitrary commands on the remote host.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Disable this suite or upgrade to the latest version'
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.s-quadra.com/advisories/Adv-20040303.txt'
  );

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/03/04");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/03/05");
 script_cvs_date("$Date: 2016/12/14 20:33:26 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_dependencies("http_version.nasl", "no404.nasl");
 script_require_keys("www/ASP");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);

foreach dir (cgi_dirs())
{
 w = http_send_recv3(method:"GET", item: dir + "/viewCart.asp?userID='", port: port );
 if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
 res = strcat(w[0], w[1], '\r\n', w[2]);
 if ( egrep(pattern:"userID=''' and storeID=", string:res) )
   {
	security_hole ( port );
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit ( 0 );
   }
}
