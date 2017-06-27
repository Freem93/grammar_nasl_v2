#
# (C) Tenable Network Security, Inc.
#

#
# Ref: http://www.geocities.com/sjefferson101010/ (link is broken)
#


include("compat.inc");

if(description)
{
  script_id(11684);
  script_version ("$Revision: 1.12 $");
  script_osvdb_id(53999);
  script_cvs_date("$Date: 2013/01/25 01:19:10 $");

  script_name(english:"rot13sj.cgi Arbitrary File Access");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary commands can be run on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the CGI 'rot13sj.cgi'. This CGI contains 
various flaws which may allow a user to execute arbitrary commands on 
this host and to read aribrary files." );
 script_set_attribute(attribute:"solution", value:
"Delete this CGI." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/03");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks for rot13sj.cgi");
 script_category(ACT_ATTACK);  
 script_copyright(english:"This script is Copyright (C) 2003-2013 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

foreach dir (make_list(cgi_dirs()))
{ 
 r = http_send_recv3(method: "GET", item: dir + "/rot13sj.cgi?/etc/passwd", port:port);
 if (isnull(r)) exit(0);
 
 #
 # Every file is rot13-encoded
 #

 if(egrep(pattern:"ebbg:.*:0:[01]:.*", string: r[0]+r[1]+r[2]))
 {
  security_hole(port);
  exit(0);
 }
}

