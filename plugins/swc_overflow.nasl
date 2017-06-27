#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added link to the Bugtraq message archive and Securiteam

include( 'compat.inc' );

if(description)
{
  script_id(10493);
  script_version ("$Revision: 1.28 $");
  script_osvdb_id(392);
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_name(english:"Simple Web Counter swc ctr Parameter Remote Overflow");
  script_summary(english:"Checks for the presence of /cgi-bin/swc");

   script_set_attribute(
    attribute:'synopsis',
    value:'The remote CGI script is vulnerable to a buffer overflow.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The CGI \'swc\' (Simple Web Counter) is present and vulnerable
to a buffer overflow when issued a too long value to the
\'ctr=\' argument.

An attacker may use this flaw to gain a shell on this host.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Use another web counter, or patch this one by hand.'
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.securiteam.com/unixfocus/5FP0O202AE.html'
  );


 script_set_attribute(attribute:"plugin_publication_date", value: "2000/08/24");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/08/22");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
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
 w = http_send_recv3(method:"GET", item:string(dir, "/swc?ctr=", crap(500)),
 	        port:port);
 if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
 r = strcat(w[0], w[1], '\r\n', w[2]);

 if("Could not open input file" >< r)
 {
   w = http_send_recv3(method:"GET", item:string(dir, "/swc?ctr=", crap(5000)), port:port);
   if (w[0] =~ "HTTP/[0-9]\.[0-9] 500 ") security_hole(port);
 }
}
