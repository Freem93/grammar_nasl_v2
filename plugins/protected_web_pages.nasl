#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(40665);
 script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2016/10/04 15:39:24 $");
 
 script_name(english: "Protected Web Page Detection");
 script_summary(english:"Displays pages that require authentication.");
 
 script_set_attribute(attribute:"synopsis", value:
"Some web pages require authentication.");
 script_set_attribute(attribute:"description", value:
"The remote web server requires HTTP authentication for the following
pages. Several authentication schemes are available :

  - Basic is the simplest, but the credentials are sent in 
    cleartext.

  - NTLM provides an SSO in a Microsoft environment, but it
    cannot be used on both the proxy and the web server. It
    is also  weaker than Digest.

  - Digest is a cryptographically strong scheme. Credentials 
    are never sent in cleartext, although they may still be
    cracked by a dictionary attack.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value: "2009/08/21");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");
 
 script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

 script_dependencie("webmirror.nasl", "DDI_Directory_Scanner.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default: 80);

schemes_l = get_kb_list_or_exit("www/"+port+"/content/authentication_scheme");

report = "";
seen = make_array();

seen_url = make_array();
foreach s (schemes_l)
{
 k = tolower(s);
 if (seen[k]) continue;
 seen[k] = 1;

 report = strcat(report, '\nThe following pages are protected by the ', s, ' authentication scheme :\n\n');

 i = 0;
 while (1)
 {
   u = get_kb_item("www/" +port+ "/content/" +k+ "_auth/url/" + i);
   if (isnull(u)) break;
   if (! seen_url[u])
   {
     seen_url[u] = 1;
     r = get_kb_item("www/" +port+ "/content/" +k+ "_auth/realm/" + i);
     if (! r)
       report = report + u + ' - Realm = ' + r + '\n';
     else
       report = report + u + '\n';
   }
   i ++;
 }
 report = strcat(report, '\n');
}

if (report)
  security_note(port: port, extra: report);
