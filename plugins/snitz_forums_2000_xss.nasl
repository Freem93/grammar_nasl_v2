#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if (description)
{
  script_id(11597);
  script_version ("$Revision: 1.26 $");

  script_cve_id("CVE-2003-0492", "CVE-2003-0494");
  script_bugtraq_id(7381, 7922, 7925);
  script_osvdb_id(3297, 4320);

  script_name(english:"Snitz Forums 2000 3.4.03 Multiple Vulnerabilities");
  script_summary(english:"Determine if Snitz forums is vulnerable to xss attack");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote web application is vulnerable to injection attacks.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The remote host is using Snitz Forum 2000.

This set of CGI is vulnerable to a cross-site-scripting issue
that may allow attackers to steal the cookies of your
users.

In addition to this flaw, a user may use the file Password.ASP to
reset arbitrary passwords, therefore gaining administrative access
on this web system.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'The vendor has released a patch. http://forum.snitz.com/'
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(
    attribute:'see_also',
    value:'http://seclists.org/bugtraq/2003/Jun/127'
  );

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/07");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/06/16");
 script_cvs_date("$Date: 2016/12/14 20:33:26 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
  script_dependencie("http_version.nasl", "no404.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/ASP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

dir = list_uniq("/forum", cgi_dirs());

foreach d (dir)
{
 url = string(d, '/search.asp');
 r = http_send_recv3(method: "GET", item:url, port:port);
 if (isnull(r)) exit(0);

 # Ex: Powered By: Snitz Forums 2000 Version 3.4.03
 if ("Powered By: Snitz Forums 2000" >< r[2])
   {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
   }
}
