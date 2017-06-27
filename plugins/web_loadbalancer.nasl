#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(12224);
 script_version ("$Revision: 1.19 $");
 script_cvs_date("$Date: 2013/01/25 01:19:11 $");

 script_name(english:"Web Server Load Balancer Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is load-balanced." );
 script_set_attribute(attribute:"description", value:
"The remote web server seems to be running in conjunction with several
others behind a load balancer.  Knowing that there are multiple
systems behind a service could be useful to an attacker as the
underlying hosts may be running different operating systems,
patchlevels, etc." );
 script_set_attribute(attribute:"solution", value:
"Update the web configuration to hide information disclosure." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/05/04");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Web Server load balancer detection");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


# so, saw this on FD today:
#Date: Tue,  4 May 2004 11:30:35 -0700
#From: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
#To: full-disclosure@lists.netsys.com
#Subject: RE: [Full-Disclosure] A FreeBSD server that is converted in a MS 2003 Server... and viceversa
#
#> I have access to a FreeBSD server, I accessed and look a little.
#> The problem is when sometimes I have not access anymore, and its
#> because the server is not a FreeBSD, is a MS 2003 Server... :(
#
#Sounds like the round robin DNS exploit or possibly the multi-os load
#balancing vulnerability.  Could be that new self-morphing, dynamic reconfigurator
#rootkit, too.  Sounds evil in any case.
#
# I thought it would be neat if Nessus could find multiple hosts (sometimes *internal* hosts :-) )
# behind a single IP


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);

# We are purposely *not* setting the Host: header AND using HTTP/1.0
rq = http_mk_get_req(port: port, item: "/images", version: 10);
rq["Host"] = NULL;

# make sure we get a 302
w = http_send_recv_req(port: port, req: rq, follow_redirect: 0);
if (isnull(w)) exit(0);

if (! ereg(string: w[0], pattern:"^HTTP/.* 302 ") ) exit(0); 


# looks like :
# HTTP/1.1 302 Object Moved
# Location: http://x.x.x.x/images/
# Server: Microsoft-IIS/5.0
# Content-Type: text/html
# Content-Length: 152

urlz = make_list();
last = "";
diffcounter = 0;

for (i=0; i<20; i++) {
  w = http_send_recv_req(port: port, req: rq, follow_redirect: 0);
  if (isnull(w)) break;

  pat = "^Location: *https?://";
  matches = egrep(pattern:pat, string:w[1]);
  if (matches) {
    foreach line (split(matches)) {
      line = chomp(line);
      loc = strstr(line, "http");
      myurl = ereg_replace(pattern:"^(https?://[^/?;]*).*$", replace:"\1", string:loc);

      if (myurl != last && myurl != NULL ) {
        diffcounter++; 
        urlz = make_list(urlz, loc);
      }
      last = myurl;
    }
  }
}    

if (diffcounter) {
  counter  = 0;
  info = "";

  foreach z (urlz) {info += string("  ", z,"\n"); counter ++;}

  if (counter > 1) {
    if (report_verbosity) {
      report = string(
        "\n",
        "Nessus queried the remote web server 20 times and was redirected to\n",
        "the following locations :\n",
        "\n",
        info
      );
      security_note(port:port, extra:report);
    }
    else security_note(port);
  }
}
