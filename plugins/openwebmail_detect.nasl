#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#



include("compat.inc");

if (description) {
  script_id(14221);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $"); 

  script_name(english:"Open WebMail Detection");
  script_summary(english:"Checks for the presence of Open WebMail");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a webmail application." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Open WebMail, a webmail package written in
Perl that provides access to mail accounts via POP3 or IMAP." );
 script_set_attribute(attribute:"see_also", value:"http://www.openwebmail.org/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/10");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2015 George A. Theall");

  script_dependencie("http_version.nasl", "no404.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (get_kb_item("www/no404/" + port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/cgi-bin/openwebmail", "/openwebmail-cgi", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = 0;
foreach dir (dirs) {
  url = string(dir, "/openwebmail.pl");
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (isnull(res)) exit(0);             # can't connect

  # If the page refers to Open WebMail, try to get its version number.
  if (
    egrep(string:res, pattern:"^HTTP/.* 200 OK") &&
    egrep(string:res, pattern:"(http://openwebmail\.org|Open WebMail)")
  ) {
    # First see if version's included in the form. If it is, Open WebMail 
    # puts it on a line by itself, prefixed by the word "version".
    pat = "^version (.+)$";
    matches = egrep(pattern:pat, string:res);
    foreach match (split(matches)) {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver)) ver = ver[1];
      break;                            # nb: only worried about first match.
    }

    # If that didn't work, looking for it in doc/changes.txt,
    # under the Open WebMail data directory.
    if (isnull(ver)) {
      # Identify data directory from links to images or help files.
      pat = '([^\'"]*/openwebmail)/(images|help)/';
      matches = egrep(pattern:pat, string:res);
      foreach match (split(matches)) {
        match = chomp(match);
        data_url = eregmatch(string:match, pattern:pat);
        if (!isnull(data_url)) data_url = data_url[1];
        break;                          # nb: only worried about first match.
      }
      # Try to get doc/changes.txt under data directory.
      if (!isnull(data_url)) {
        url = string(data_url, "/doc/changes.txt");
        req = http_get(item:url, port:port);
        res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
        if (isnull(res)) exit(0);       # can't connect

        # Try to get version number.
        #
        # nb: this won't identify intermediate releases, only full ones.
        if (egrep(string:res, pattern:"^HTTP/.* 200 OK")) {
          rel = NULL;
          pat = "^[0-1][0-9]/[0-3][0-9]/20[0-9][0-9]( +.version .+)?";
          matches = egrep(pattern:pat, string:res);
          foreach match (split(matches)) {
            match = chomp(match);
            ver = eregmatch(pattern:"version +(.+).$", string:match);
            if (isnull(ver)) {
              # nb: only first release date matters.
              if (isnull(rel)) {
                # Rearrange date: mm/dd/yyyy -> yyyyddmm.
                parts = split(match, sep:"/", keep:FALSE);
                rel = string(parts[2], parts[0], parts[1]);
              }
            }
            else {
              ver = ver[1];
              if (!isnull(rel)) ver = string(ver, " ", rel);
              break;                    # nb: only worried about first match.
            }
          }
        }
      }
    }

    # If still unknown, just mark it as "unknown".
    if (isnull(ver)) ver = "unknown";

    if (dir == "") dir = "/";
    set_kb_item(
      name:string("www/", port, "/openwebmail"), 
      value:string(ver, " under ", dir)
    );
    installations[dir] = ver;
    ++installs;
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
      info = string("An unknown version of Open WebMail was detected on the remote\nhost under the path '", dir, "'.");
    }
    else {
      info = string("Open WebMail ", ver, " was detected on the remote host under\nthe path '", dir, "'.");
    }
  }
  else {
    info = string(
      "Multiple instances of Open WebMail were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", installations[dir], ", installed under ", dir, "\n");
    }
    info = chomp(info);
  }

  security_note(port:port, extra:'\n'+info);
}
