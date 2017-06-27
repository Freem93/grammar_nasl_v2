#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#


# NB: I define the script description here so I can later modify
#     it with the version number and install directory.

include("compat.inc");

if (description) {
  script_id(13858);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");
 
  name["english"] = "osTicket Detection";
  script_name(english:name["english"]);
  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a support ticket system." );
 script_set_attribute(attribute:"description", value:
"The remote host is running osTicket, a PHP-based, open source support
ticket system." );
 script_set_attribute(attribute:"see_also", value:"http://www.osticket.com/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/30");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value: "cpe:/a:osticket:osticket");
 script_end_attributes();

 
  summary["english"] = "Checks for the presence of osTicket";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 George A. Theall");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(1);
if (!can_host_php(port:port)) exit(1);


# Search for osTicket.
installs = 0;
foreach dir (cgi_dirs()) {
  # Get osTicket's open.php.
  url = string(dir, "/open.php");
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(1);

  # Make sure the page is from osTicket.
  if (egrep(pattern:'alt="osTicket', string:res, icase:TRUE)) {
    pat = "alt=.osTicket STS v(.+) *$";
    matches = egrep(pattern:pat, string:res);
    foreach match (split(matches)) {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (ver == NULL) break;
      ver = ver[1];

      # 1.2.5, 1.2.7, and 1.3.x all report 1.2; try to distinguish among them.
      if (ver == "1.2") {
        # 1.3.0 and 1.3.1.
        if ("Copyright &copy; 2003-2004 osTicket.com" >< res) {
          # nb: 1.3.1 doesn't allow calling 'include/admin_login.php' directly.
          url = string(dir, "/include/admin_login.php");
          req = http_get(item:url, port:port);
          res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
          if (res == NULL) exit(1);

          if ("<td>Please login:</td>" >< res) {
            ver = "1.3.0";
          }
          else if ("Invalid path" >< res) {
            ver = "1.3.1";
          }
          else {
            ver = "unknown";
            debug_print("can't determine version (1.3.x series)", level:1);
          }
        }
        # 1.2.5 and 1.2.7
        else {
          # nb: 1.2.5 has an attachments dir whereas 1.2.7 has attachments.php
          url = string(dir, "/attachments.php");
          req = http_get(item:url, port:port);
          res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
          if (res == NULL) exit(1);

          if ("You do not have access to attachments" >< res) {
            ver = "1.2.7";
          }
          else if ("404 Not Found" >< res) {
            ver = "1.2.5";
          }
          else {
            ver = "unknown";
            debug_print("can't determine version (1.2.x series)", level:1);
          }
        }
      }

      # Success!
      set_kb_item(
        name:string("www/", port, "/osticket"), 
        value:string(ver, " under ", dir)
      );
      set_kb_item(name: "www/osticket", value: TRUE);
      installations[dir] = ver;
      ++installs;

      # nb: only worried about the first match.
      break;
    }
  }
  # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
  if (installs && !thorough_tests) break;
}

# Report any instances found unless Report verbosity is "Quiet".
if (installs && report_verbosity > 0) {
  if (installs == 1) {
    foreach dir (keys(installations)) {
      # empty - just need to set 'dir'.
    }
    if (ver == "unknown") {
      info = string("An unknown version of osTicket was detected on the remote host under\nthe path ", dir, ".");
    }
    else {
      info = string("osTicket ", ver, " was detected on the remote host under the path ", dir, ".");
    }
  }
  else {
    info = string(
      "Multiple instances of osTicket were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", installations[dir], ", installed under ", dir, "\n");
    }
    info = chomp(info);
  }

  security_note(port:port, extra: info);
}
