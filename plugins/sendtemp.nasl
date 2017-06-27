#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10614);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-2001-0272");
 script_bugtraq_id(2504);
 script_osvdb_id(510);

 script_name(english:"W3.org Anaya Web sendtemp.pl 'templ' Parameter Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary files may be read on the remote server.");
 script_set_attribute(attribute:"description", value:
"The 'sendtemp.pl' CGI is installed. This CGI has a well known
security flaw that allows an attacker read arbitrary files with the
privileges of the HTTP daemon.");
 script_set_attribute(attribute:"solution", value:
"Remove it from /cgi-bin." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/02/15");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/02/12");

 script_cvs_date("$Date: 2015/08/19 20:20:34 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Checks for the presence of /cgi-bin/sendtemp.pl");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

foreach dir (cgi_dirs())
{
 u = strcat(dir, "/sendtemp.pl?templ=../../../../../etc/passwd");
 r = http_send_recv3(port: port, method: "GET", item: u);
 if (isnull(r)) exit(0);
 if(egrep(pattern:".*root:.*:0:[01]:.*", string: r[1]+r[2]))
 {
  security_hole(port, extra: "Clicking on this URL should exhibit the flaw :\n" + build_url(port: port, qs: u));
  exit(0);
 }
}
