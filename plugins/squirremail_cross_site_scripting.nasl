#
# (C) Tenable Network Security, Inc.
#

#
# This script was rewritten by Tenable Network Security, Inc., using a new HTTP API.
#
# Did not really check CVE-2002-1276, since it`s the same kind of problem.
#


include("compat.inc");

if (description)
{
 script_id(11415);
 script_version ("$Revision: 1.32 $");

 script_cve_id("CVE-2002-1341");
 script_bugtraq_id(6302);
 script_osvdb_id(4266);
 script_xref(name:"RHSA", value:"2003:0042-07");

 script_name(english:"SquirrelMail 1.2.9 / 1.2.10 read_body.php Multiple Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a cross-site scripting
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be vulnerable to a security problem in
SquirrelMail. The 'read_body.php' script doesn't filter out user
input for multiple parameters, allowing for XSS attacks." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to a newer version of this software." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/12/02");
 script_cvs_date("$Date: 2015/01/23 22:03:56 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:squirrelmail:squirrelmail");
script_end_attributes();

 script_summary(english:"Determine if a remote host is vulnerable to xss attack");
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

test_cgi_xss(port: port, cgi: "/read_body.php", dirs: cgi_dirs(),
 qs: "mailbox=<script>alert(document.cookie)</script>&passed_id=<script>alert(document.cookie)</script>&startMessage=1&show_more=0",
 pass_str: "<script>alert(document.cookie)</script>" );
