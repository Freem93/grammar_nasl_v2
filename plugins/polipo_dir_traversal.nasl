#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(19940);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2005-3163");
  script_bugtraq_id(14970);
  script_osvdb_id(19693);

  script_name(english:"Polipo < 0.9.9 Unspecified Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server may expose files outside the local web root." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the Polipo caching web proxy.  In addition to
caching web pages, the software also functions as a web server for
providing access to documentation, cached pages, etc. 

The built-in web server in the installed version of Polipo fails to
filter directory traversal sequences from requests.  By exploiting this
issue, an attacker may be able to retrieve files located outside the
local web root, subject to the privileges of the userid under which
Polipo runs." );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/mailarchive/forum.php?thread_id=6845581&forum_id=36515" );
 script_set_attribute(attribute:"see_also", value:"http://www.pps.jussieu.fr/~jch/software/polipo/CHANGES.text" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Polipo 0.9.9 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/10/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/09/23");
 script_cvs_date("$Date: 2011/03/14 21:48:11 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_summary(english:"Checks for local web root restriction bypass vulnerability in Polipo");
  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 8123);
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8123);


# Make sure the banner indicates it's Polipo.
banner = get_http_banner(port:port);
if (banner && "Polipo" >< banner) {
  # Flag it as a proxy too.
  register_service(port:port, ipproto:"tcp", proto:"http_proxy");

  # Try to exploit the flaw.
  url = string("/../", SCRIPT_NAME, "/", rand_str());
  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if the error suggests our request was unfiltered.
  if (egrep(string:res, pattern:string("The proxy on .+ error while fetching <strong>", url))) {
    security_warning(port);
    exit(0);
  }
}

