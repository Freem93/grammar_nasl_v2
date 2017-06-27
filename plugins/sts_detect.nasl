#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(42822);
 script_version ("$Revision: 1.6 $");

 script_name(english:"Strict Transport Security (STS) Detection");
 script_summary(english:"Checks if the web server supports STS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server implements Strict Transport Security.");
 script_set_attribute(attribute:"description", value:
"The remote web server implements Strict Transport Security (STS).
The goal of STS is to make sure that a user does not accidentally
downgrade the security of his or her browser.

All unencrypted HTTP connections are redirected to HTTPS.  The browser
is expected to treat all cookies as 'secure' and to close the
connection in the event of potentially insecure situations.");
 # http://lists.w3.org/Archives/Public/www-archive/2009Sep/att-0051/draft-hodges-strict-transport-sec-05.plain.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fb3aca6");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/16");
 script_cvs_date("$Date: 2013/11/19 23:27:54 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
 script_family(english:"Service detection");
 # We could run earlier, but that is not necessary
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:443, embedded: 1);

r = http_get_cache(port: port, item:"/", exit_on_fail: 1);

sts = egrep(string: r, pattern: "^Strict-Transport-Security:");
if (!sts) exit(0, "The web server on port "+port+" does not implement STS.");
else
{
  rep = strcat('\nThe STS header line is :\n\n', chomp(sts), '\n');
  security_note(port: port, extra: rep);
  set_kb_item(name:"www/"+port+"/STS", value:TRUE);
}
