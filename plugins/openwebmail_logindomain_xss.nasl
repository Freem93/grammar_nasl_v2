#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

# Changes by Tenable:
# - Revised plugin title (5/21/09)


include("compat.inc");

if (description) {
  script_id(16463);
  script_version("$Revision: 1.12 $");
  script_cve_id("CVE-2005-0445");
  script_bugtraq_id(12547);
  script_osvdb_id(13788);

  script_name(english:"Open WebMail openwebmail.pl logindomain Parameter XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote webmail server is affected by a cross-site scripting flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host is running at least one instance of Open WebMail that
fails to sufficiently validate user input supplied to the 'logindomain'
parameter.  This failure enables an attacker to run arbitrary script
code in the context of a user's web browser." );
 script_set_attribute(attribute:"see_also", value:"http://openwebmail.org/openwebmail/download/cert/advisories/SA-05:01.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Open WebMail version 2.50 20040212 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/02/14");
 script_cvs_date("$Date: 2015/01/14 20:12:25 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Checks for logindomain parameter cross-site scripting vulnerability in Open WebMail";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005-2015 George A. Theall");

  family["english"] = "CGI abuses : XSS";
  script_family(english:family["english"]);

  script_dependencie("openwebmail_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);

# We test whether the hole exists by trying to echo magic (urlencoded
# as alt_magic for http) and checking whether we get it back.
magic = "logindomain xss vulnerability";
alt_magic = str_replace(string:magic, find:" ", replace:"%20");


# Test an install.
install = get_kb_item(string("www/", port, "/openwebmail"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  url = string( "/openwebmail.pl?logindomain=%22%20/%3E%3Cscript%3Ewindow.alert('",
    alt_magic,
    "')%3C/script%3E"
  );
  debug_print("retrieving '", url, "'.");
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (isnull(res)) exit(0);           # can't connect
  debug_print("res =>>", res, "<<");

  if (egrep(string:res, pattern:magic)) {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
