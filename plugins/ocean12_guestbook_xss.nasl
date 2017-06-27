#
# (C) Tenable Network Security, Inc.
#
# Ref: 
#  From: "drG4njubas" <drG4nj@mail.ru>
#  To: <bugtraq@securityfocus.com>
#  Subject: Ocean12 ASP Guestbook Manager v1.00
#  Date: Fri, 11 Apr 2003 16:29:16 +0400



include("compat.inc");

if(description)
{
 script_id(11537);
 script_bugtraq_id(7329);
 script_version ("$Revision: 1.18 $");
 
 name["english"] = "Ocean12 Guestbook XSS";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server has an application that is affected by
a cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote server is running Ocean12 GuestBook, a set of scripts
to manage an interactive guestbook.

An attacker may use this module to inject malicious HTML code in your
site, which may be used to steal users' cookies or to simply annoy 
them." );
 script_set_attribute(attribute:"solution", value:
"Disable this software." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/04/14");
 script_cvs_date("$Date: 2015/01/14 20:12:25 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Checks for Ocean12 guestbook";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);


dirs = list_uniq(cgi_dirs(), "/guestbook");

foreach d (dirs)
{
 u = string(d, "/");
 r = http_send_recv3(method: "GET", item: u, port:port);
 if (isnull(r)) exit(0);
 if("Ocean<i>12</i>" >< r[2])
 {
  vers = strstr(r[2], "ASP Guestbook Manager</a> v1.00");
  if(vers)
  {
    if (report_verbosity > 1)
     security_warning(port, 
 extra: strcat('\nOcean12 GuestBook was found at:\n', build_url(port: port, qs: u), '\n'));
    else
     security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
  exit(0);
 }
}
