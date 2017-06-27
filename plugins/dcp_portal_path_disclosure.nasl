#
# (C) Tenable Network Security, Inc.
#
# Ahmet Sabri ALPER <s_alper@hotmail.com>
# To:  BugTraq
# Subject:  [ARL02-A02] DCP-Portal Root Path Disclosure Vulnerability


include("compat.inc");

if (description)
{
 script_id(11477);
 script_bugtraq_id(4113);
 script_osvdb_id(7015, 7016, 7017, 7018);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2002-0282");
 script_name(english:"DCP-Portal Multiple Script Path Disclosure");
 script_set_attribute(attribute:"synopsis", value:
"The remote host may be prone to an information disclosure issue." );
 script_set_attribute(attribute:"description", value:
"DCP-Portal discloses its physical path when an empty request
to add_user.php is made

In addition, several other scripts may disclose the path if an
invalid language is supplied, although Nessus has not checked
for them." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to a newer version." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/02/15");
 script_cvs_date("$Date: 2011/03/13 23:54:23 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Determine if DCP-Portal displays its physical path");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);
if ( ! can_host_php(port:port) ) exit(0);

		


foreach d (cgi_dirs())
{
 url = string(d, "/add_user.php");
 r = http_send_recv3(method: "GET", item:url, port:port);
 if (isnull(r)) exit(0);
 buf = strcat(r[0], r[1], '\r\n', r[2]);

 if(egrep(pattern:".*Warning:.*output started at /.*", string:buf))
   {
    security_warning(port);
    exit(0);
   }
}
