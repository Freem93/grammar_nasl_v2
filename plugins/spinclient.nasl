#
# (C) Tenable Network Security, Inc.
#

#
# Thanks to Tollef Fog Heen <tfheen@opera.no> for his help

include( 'compat.inc' );

if(description)
{
 script_id(10393);
 script_version ("$Revision: 1.25 $");
 script_osvdb_id(54034);

 script_name(english:"spin_client.cgi Remote Overflow");
 script_summary(english:"Checks for the /cgi-bin/spin_client.cgi buffer overrun");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote CGI script is vulnerable to a buffer overflow.'
  );

  script_set_attribute(
    attribute:'description',
    value:'There is a buffer overrun in the \'spin_client.cgi\'
CGI program, which will allow anyone to execute arbitrary
commands with the same privileges as the web server (root or nobody).'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Remove \'spin_client.cgi\' from the server or contact your vendor for a fix.'
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");


 script_set_attribute(attribute:"plugin_publication_date", value: "2000/05/03");
 script_cvs_date("$Date: 2016/12/14 20:33:26 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# This CGI is tricky to check for.
#
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

foreach dir (cgi_dirs())
{
 if (is_cgi_installed3(item:string(dir, "/spin_client.cgi"), port:port))
 {
  w = http_send_recv3(method:"GET", port: port,
    item: dir+"/spin_client.cgi?"+crap(8), exit_on_fail: 1,
    add_headers: make_array("User-Agent", crap(8)) );
  if (w[0] =~ "^HTTP\/[0-9]\.[0-9] 200 ")
   {
   w = http_send_recv3(method: "GET ", port: port,
     item: dir+"/spin_client.cgi?"+crap(8000), exit_on_fail: 1,
     add_headers: make_array("User-Agent", crap(8000)));
   if(w[0] =~ "^HTTP\/[0-9]\.[0-9] 500 ")
   {
   	security_hole(port);
   }
  }
 }
}
