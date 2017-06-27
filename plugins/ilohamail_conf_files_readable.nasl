#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

# Changes by Tenable:
# - output formatting, family change (9/5/09)


include("compat.inc");

if (description) {
  script_id(16142);
  script_version("$Revision: 1.12 $");
  script_bugtraq_id(12252);
  script_osvdb_id(12870);

# script_cve_id("CVE-MAP-NOMATCH");
# NOTE: no CVE id assigned (gat, 01/2005)
 
  script_name(english:"IlohaMail Multiple Configuration Files Remote Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The target is running at least one instance of IlohaMail that allows
anyone to retrieve its configuration files over the web.  These files
may contain sensitive information. For example, conf/conf.inc may
hold a username / password used for SMTP authentication." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Jan/118" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to IlohaMail version 0.8.14-rc2 or later or
reinstall following the 'Proper Installation' instructions 
in the INSTALL document." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/12");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/11");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_summary(english:"Checks for Readable Configuration Files in IlohaMail");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 George A. Theall");
  script_family(english:"CGI abuses");
  script_dependencie("global_settings.nasl", "ilohamail_detect.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
debug_print("searching for readable configuration files in IlohaMail on port ", port, ".");

# Check each installed instance, stopping if we find a vulnerable version.
installs = get_kb_list(string("www/", port, "/ilohamail"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    debug_print("checking version ", ver, " under ", dir, ".");

    # If this was a quick & dirty install, try to grab a config file.
    if (dir =~ "/source$") {
      dir = ereg_replace(string:dir, pattern:"/source$", replace:"/conf");
      # nb: conf.inc appears first in 0.7.3; mysqlrc.inc was used
      #     as far back as 0.7.0.
      foreach config (make_list("conf.inc", "mysqlrc.inc")) {
        url = string(dir, "/", config);
        debug_print("retrieving ", url, "...");
        req = http_get(item:url, port:port);
        res = http_keepalive_send_recv(port:port, data:req);
        if (res == NULL) exit(0);           # can't connect
        debug_print("res =>>", res, "<<.");

        # Does it look like PHP code with variable definitions?
        if (egrep(string:res, pattern:"<\?php") && egrep(string:res, pattern:"\$[A-Za-z_]+ *= *.+;")) {
#        if (egrep(string:res, pattern:"<\?php")) {
#          display("It's php code!\n");
#          if (egrep(string:res, pattern:"\$[A-Za-z_]+ *= *.+;")) {
#            display("It's got variable assignments!\n");
          security_warning(port:port);
          exit(0);
#}
        }
      }
    }
  }
}
