#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(29871);
 script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2016/11/29 20:13:37 $");

 script_name(english:"Web Server Malicious JavaScript Link Detection");
 script_summary(english:"This plugin uses the results of webmirror.nasl");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server seems to have been compromised by malware.");
 script_set_attribute(attribute:"description", value:
"The remote web server seems to link to malicious JavaScript files
hosted on a third-party website.

This typically means that the remote web server has been compromised,
and it may infect its visitors as well.");
 script_set_attribute(attribute:"solution", value:
"Restore your web server to its original state, and audit your dynamic
pages for SQL injection vulnerabilities.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d8fa1760");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ca2eff80");

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/08");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("webmirror.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 1);

list = get_kb_list("www/" + port + "/infected/pages");
if ( isnull(list) ) exit(0, "No infected page was found on port "+port+".");
list = make_list(list);
report = "";
foreach item ( list )
{
 if ( item =~ "link: " ) 
 {
  item = str_replace(find:"page:", replace:"The URL " + build_url(port:port, qs: "/"), string:item);
  item = str_replace(find:"link:", replace:"links to:", string:item);
  # Add malware's name if it has one
  if ('/ur.php' >< item) item += ' [Lizamoon]';
  if (ereg(pattern:"^http://(lilupophilupop\.com|lasimp04risoned\.rr\.nu|eighbo02rsbarr\.rr\.nu|reque83ntlyin\.rr\.nu|tentsf05luxfig\.rr\.nu|andsto57cksstar\.rr\.nu|brown74emphas\.rr\.nu|tartis78tscolla\.rr\.nu|senior78custome\.rr\.nu|sfl20ewwa\.rr\.nu|ksstar\.rr\.nu|enswdzq112aazz\.com|www\.bldked98f5\.com|www1\.mainglobilisi\.com|xinthesidersdown\.com|inglon03grange\.rr\.nu|senior78custome\.rr\.nu)/sl\.php$", string:item, icase:TRUE)) item += ' [Lilupophilupop]';
  if (item =~ 'http://(nikjju|hgbyju)\\.com') item += ' [Nikjju]';
  #
  report += item + '\n';
 }
}

if ( strlen(report) )
{
 security_hole(port:port, extra: report);
 set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
}
