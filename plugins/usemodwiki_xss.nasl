#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(15967);
 script_version ("$Revision: 1.22 $");

 script_cve_id("CVE-2004-1397");
 script_bugtraq_id(11924);
 script_xref(name:"OSVDB", value:"12368");

 script_name(english:"UseModWiki wiki.pl XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server has a CGI script that is prone to cross-site
scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is using UseModWiki, a wiki CGI written in Perl. 

The CGI 'wiki.pl' is vulnerable to a cross-site-scripting issue that
may allow attackers to steal the cookies of third parties." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=110305173302388&w=2" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/12/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/12/09");
 script_cvs_date("$Date: 2015/01/15 03:38:17 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/07/09");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Determine if wiki.pl is vulnerable to xss attack");
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);

if ( get_kb_item("www/"+port+"/generic_xss") ) exit(0);

test_cgi_xss(dirs: cgi_dirs(), cgi: '/wiki.pl', qs: '<script>foo</script>',
 pass_str: '<H2>Invalid Page <script>foo<', port: port);
