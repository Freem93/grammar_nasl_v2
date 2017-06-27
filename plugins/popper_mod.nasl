#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11334);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2002-0513");
 script_bugtraq_id(4412);
 script_osvdb_id(5273);
 
 script_name(english:"popper_mod PHP Administration Script Authentication Bypass");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to gain administrative rights on the remote POP server.");
 script_set_attribute(attribute:"description", value:
"It is possible to administrate the remote popper_mod CGI by requesting
the /admin directory directly.

An attacker may use this flaw to obtain the passwords of your users." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/09");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/04/09");
 script_cvs_date("$Date: 2011/03/14 21:48:11 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks if popper_mod is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl");
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

foreach dir (make_list(cgi_dirs(), "/mail"))
{
 u = dir+"/admin/";
 r = http_send_recv3(method: "GET", item: u, port:port);
 if (isnull(r)) exit(0);
 
 # The typo below is included in the software.
 if("webmail Adminstration" >< r[2])
 {
   security_hole(port, extra: strcat('\npopper_mod was found under :\n\n', build_url(port: port, qs: u), '\n'));
   break;
 }
}
