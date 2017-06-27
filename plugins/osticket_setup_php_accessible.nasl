#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#



include("compat.inc");

if (description) {
  script_id(13647);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/01/25 01:19:09 $");
 
  script_name(english:"osTicket setup.php Accessibility");
 
 script_set_attribute(attribute:"synopsis", value:
"Application data may be modified or delete on this host." );
 script_set_attribute(attribute:"description", value:
"The target is running at least one instance of an improperly secured
installation of osTicket and allows access to setup.php.  Since that
script does not require authenticated access, it is possible for an
attacker to modify osTicket's configuration using a specially crafted
call to setup.php to perform the INSTALL actions. 

For example, if config.php is writable, an attacker could change the
database used to store ticket information, even redirecting it to
another site.  Alternatively, regardless of whether config.php is
writable, an attacker could cause the loss of all ticket information by
reinitializing the database given knowledge of its existing
configuration (gained, say, from reading config.php)." );
 script_set_attribute(attribute:"solution", value:
"Remove both setup.php and gpcvar.php and ensure permissions
on config.php are 644." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/14");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Checks Accessibility of osTicket's setup.php";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 George A. Theall");

  script_family(english:"CGI abuses");

  script_dependencie("global_settings.nasl", "http_version.nasl", "osticket_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/osticket");
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

host = get_host_name();
port = get_http_port(default:80);
if (debug_level) display("debug: searching for setup.php Accessibility vulnerability in osTicket on ", host, ":", port, ".\n");

if (!get_port_state(port)) exit(0);

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/osticket"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    if (debug_level) display("debug: checking version ", ver, " under ", dir, ".\n");

    # Get osTicket's setup.php.
    url = string(dir, "/setup.php");
    if (debug_level) display("debug: checking ", url, ".\n");
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if (res == NULL) exit(0);           # can't connect
    if (debug_level) display("debug: res =>>", res, "<<\n");

    # If successful, there's a problem.
    if (egrep(pattern:"title>osTicket Install", string:res, icase:TRUE)) {
      security_warning(port:port);
      exit(0);
    }
  }
}
