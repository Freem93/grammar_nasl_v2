#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(57640);
 script_version("$Revision: 1.9 $");
 script_cvs_date("$Date: 2015/10/21 20:34:21 $");

 script_name(english:"Web Application Information Disclosure");
 script_summary(english:"Identifies the remote physical path to some remote apps.");

 script_set_attribute(attribute:"synopsis", value:"The remote web application discloses path information.");
 script_set_attribute(attribute:"description", value:
"At least one web application hosted on the remote web server discloses
the physical path to its directories when a malformed request is sent
to it.

Leaking this kind of information may help an attacker fine-tune
attacks against the application and its backend.");
 script_set_attribute(attribute:"solution", value:"Filter error messages containing path information.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/25");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_END);
 script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl", "webmirror.nasl", "web_app_test_settings.nasl");
 script_require_keys("Settings/enable_web_app_tests");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("torture_cgi.inc");
include("torture_cgi_sql_inj_msg.inc");

port = get_kb_item_or_exit("Services/www");

resp_l = get_kb_list("www/"+port+"/cgi_*/response*/*");

db = make_array();
patterns = make_list(
  '(^|[^A-Za-z])([A-Za-z]:\\\\([^/:*?\"<>|\\\\]+\\\\?)+)',
  '(^|[^/a-zA-Z0-9]+)/(Library|root|var|etc|home|bin|opt|private|usr)(/([^/<>: ]+/?)+)'
);

foreach k (keys(resp_l))
 {
    v = eregmatch(string: k, pattern: "/cgi_([A-Z][A-Z])/response([0-9]*)/([0-9]+)");
    if (isnull(v)) continue;
    code = v[1]; idx = v[2]; nb = v[3];
    k2 = str_replace(string: k, find: "/response"+idx+"/", replace: "/request"+idx+"/");
    req = get_kb_item(k2);
    req = decode_kb_blob(value:req);
    # Ignore phpMyAdmin's Documentation.html file.
    if ("/documentation.html" >< tolower(req)) continue;

    resp = decode_kb_blob(value:resp_l[k]);
    # Ignore Tomcat /appdev/processes*.html and /docs/*.html files
    if (ereg(
       pattern : "(/appdev/.*\.html|docs/.*\.html)",
       string  : tolower(req),
       multiline :TRUE)
    )
    {
      if (ereg(
        pattern : "Tomcat",
        string  : resp,
        icase   : TRUE,
        multiline : TRUE)
     ) continue;
    }

    foreach p ( patterns )
    {
     txt = extract_pattern_from_resp(string: resp, pattern: "RE:"+p, dont_clean: 0);

     # ignore dreamweaver library files
     if("#BeginLibraryItem" >< txt) continue;

     # ignore paths with directory traversal strings
     item = eregmatch(pattern:p, string:txt);
     if(item[0] =~ "\.\.[\.]*[\\/]") continue;

     # ASCII characters only in output
     if(txt !~ "^[ -~\n\r\t]+$") continue;

     if ( txt )
      {
       report += '\nThe request ' + req + '\n\nproduces the following path information :\n' + txt;
       n++;
       break;
      }
     }
    if ( n > 1024 ) { report += '\n(... many more ...)'; break; }
}

if ( n > 0 && strlen(report) ) security_warning(port:port, extra:report);
