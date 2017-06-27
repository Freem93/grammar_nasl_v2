#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16317);
 script_version ("$Revision: 1.17 $");

 script_cve_id("CVE-2005-0085");
 script_bugtraq_id(12442);
 script_osvdb_id(13520);
 script_xref(name:"DSA", value:"680");
 
 script_name(english:"ht://Dig htsearch.cgi config Parameter XSS");
 script_summary(english:"Checks if ht://Dig is vulnerable to XSS flaw in htsearch.cgi");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web search engine that is affected by a
cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of ht://Dig which is vulnerable
to an unspecified cross-site scripting attack. An attacker can exploit
this flaw to steal information from unsuspecting users." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?569e3511" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a7899e11" );
 script_set_attribute(attribute:"see_also", value:"ftp://ftp.sco.com/pub/updates/UnixWare/SCOSA-2005.45/SCOSA-2005.45.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ht://Dig 3.2.0b7 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/02/03");
 script_cvs_date("$Date: 2015/01/14 03:46:10 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

foreach dir (cgi_dirs())
{
  r = http_send_recv3(method:"GET", item:string(dir, "/htsearch.cgi"), port:port);
  if (isnull(r)) exit(1, "The web server on port "+port+" failed to respond.");
  if( egrep(pattern:"ht://Dig ([0-2]\..*|3\.([01]\..*|2\.0(a|b[0-6][^0-9])))", string:r[2] ) )
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
