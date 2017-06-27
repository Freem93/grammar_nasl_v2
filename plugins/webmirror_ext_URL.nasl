#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(49704);
 script_version("$Revision: 1.3 $");
 script_cvs_date("$Date: 2011/08/19 19:59:18 $");
 
 script_name(english:"External URLs");
 script_summary(english:"Display external URLs");
 
 script_set_attribute(attribute:"synopsis", value:
"Links to external sites were gathered." );
 script_set_attribute(attribute:"description", value:
"Nessus gathered HREF links to external sites by crawling the remote
web server." );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/04");
 script_set_attribute(attribute:"plugin_type", value: "remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("webmirror.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default: 80, embedded: 1);

n = 1;
txt = make_list();
while (1)
{
  u = get_kb_item("www/"+port+"/links/"+n);
  if (isnull(u)) break;
  r = get_kb_item("www/"+port+"/referers/"+n);
  n ++;
  len = 40 - strlen(u);
  if (len <= 0) len = 1;
  txt[n-1] = strcat(u, crap(data: ' ', length: len), '- ', r);
}
n --;

if (n == 0) exit(0, "No external URL were gathered on port "+port+".");

l = 'URL...                                  - Seen on...\n\n';
foreach line (sort(txt)) l = strcat(l, line, '\n');
txt = NULL;

e = '\n' + n + ' external URL';
if (n > 1) e += 's were'; else e += ' was';
e += ' gathered on this web server : \n';
if (COMMAND_LINE) display(e+l);
security_note(port: port, extra: e + l);
