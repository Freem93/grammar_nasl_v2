#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(43111);
 script_version ("$Revision: 1.7 $");
 script_cvs_date("$Date: 2013/05/09 21:51:46 $");

 script_name(english: "HTTP Methods Allowed (per directory)");
 script_summary(english: "Test HTTP methods on every directory");

 script_set_attribute(attribute:"synopsis", value:
"This plugin determines which HTTP methods are allowed on various CGI
directories.");
 script_set_attribute(attribute:"description", value:
"By calling the OPTIONS method, it is possible to determine which HTTP 
methods are allowed on each directory. 

As this list may be incomplete, the plugin also tests - if 'Thorough
tests' are enabled or 'Enable web applications tests' is set to 'yes'
in the scan policy - various known HTTP methods on each directory and
considers them as unsupported if it receives a response code of 400,
403, 405, or 501. 

Note that the plugin output is only informational and does not
necessarily indicate the presence of any security vulnerabilities." );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"risk_factor", value: "None" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/10" );
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");

 script_dependencie("webmirror.nasl");
 script_require_ports("Services/www", 80);
 script_timeout(900);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


StartTime = unixtime();


function mk_report(start, blah, end)
{
  local_var	tot, line, d, indent, len, l;

  indent = '    ';
  len = 0;
  foreach d (make_list(start, split(blah, sep: ' ', keep: 0), end))
  {
    l = strlen(d) + 1;
    if ((len+l) > 70)
    {
      tot = strcat(tot, line, '\n');
      line = indent;
      len = strlen(indent);
    }
    len += l;
    line = strcat(line, d, ' ');
  }
  if (len == 0) return tot;
  return strcat(tot, line, '\n');
}

tests_all_methods = 0;
if (thorough_tests || get_kb_item("Settings/enable_web_app_tests")) 
  tests_all_methods = 1;

if (tests_all_methods)
{
invalid_method = "TESTZZZ";

method_l = make_list(
#RFC 2616
 "OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT",
# RFC 2518
 "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK",
# RFC 3253
 "VERSION-CONTROL", "REPORT", "CHECKOUT", "CHECKIN", "UNCHECKOUT",
 "MKWORKSPACE", "UPDATE", "LABEL", "MERGE", "BASELINE-CONTROL", "MKACTIVITY",
#RFC 3648
 "ORDERPATCH",
# RFC 3744
  "ACL",
# draft-dusseault-http-patch
  "PATCH",
# draft-reschke-webdav-search
  "SEARCH",
# MS WebDAV Methods
 "BCOPY", "BDELETE", "BMOVE", "BPROPFIND", "BPROPPATCH", "COPY", "DELETE", 
 "LOCK", "MKCOL", "MOVE", "NOTIFY", "POLL", "PROPFIND", "PROPPATCH", "SEARCH",
 "SUBSCRIBE", "UNLOCK", "UNSUBSCRIBE", "X-MS-ENUMATTS",
# MS RPC over HTTP (Exchange)
 "RPC_IN_DATA", "RPC_OUT_DATA",
# ASP.NET
 "DEBUG",
# Netscape-Enterprise
 "INDEX",
# Should not be allowed
 invalid_method );
method_l = sort(list_uniq(method_l));

all_methods = "";
foreach m (method_l) all_methods = strcat(all_methods, ", ", m);
all_methods = substr(all_methods, 1);
}

emb = 1;
port = get_http_port(default:80, embedded: emb);

dir_l = get_kb_list(strcat("www/", port, "/content/directories"));
if (isnull(dir_l))
 dir_l = make_list("/");
else
{
 dir_l = make_list(dir_l, "/");
 dir_l = list_uniq(dir_l);
}

allow_dir = make_array();
ok_meth = make_array();
err = 0;
hdr = make_array("Content-Length", "0");
foreach dir (sort(dir_l))
{
  if ( unixtime() - StartTime > 800 ) break; # Timeout
  if (dir !~ "/$") u = strcat(dir, "/"); else u = dir;
  r = http_send_recv3(port: port, method: "OPTIONS", item: u);
  if (isnull(r))
  {
    if (err ++ >= 3) break;
  }
  else
  {
    allow = egrep(string: r[1], pattern: "^Allow:", icase: 1);
    # Normalize Allow
    if (allow)
    {
      allow = chomp(allow);
      allow = ereg_replace(string: allow, pattern: '^Allow:[ \t]*', icase: 1, replace: "");
      a = split(allow, sep: ",", keep: 0);
      a = sort(a);
      allow = "";
      foreach k (a) allow = strcat(allow, " ", chomp(k));
      allow = substr(allow, 1);
      allow_dir[allow] = strcat(allow_dir[allow], '    ', dir, '\n');
    }
    debug_print(level: 2, 'port=', port, ' dir=', dir, ' allow=', allow, '\n');
  }

  if (tests_all_methods)
  {
    a = "";
    u = strcat(u, rand_str(), ".htm");
    foreach m (method_l)
    {
      if ( unixtime() - StartTime > 800 ) break; # Timeout
      r = http_send_recv3(method: m, item: u, port: port, add_headers: hdr);
      if (isnull(r))
      {
        if (err ++ >= 3) break;
        else continue;
      }
      if (r[0] =~ "^HTTP/1\.[01] [1-5][0-9][0-9] ")
      {
        # 405 = Method Not Allowed
	# 501 = Unimplemented
	# We also use:
        # 400 = Bad request
	# 403 = Forbidden
        if (r[0] !~ "^HTTP/1\.[01] (40[035]|501) ")
        {
          a = strcat(a, " ", m);
	  debug_print(level: 2, "port=", port, " dir=", dir, " m=", m, " : ", r[0]);
        }
      }
    }
    a = substr(a, 1);
    if (a) ok_meth[a] = strcat(ok_meth[a], '    ', dir, '\n');
  }
}

rep = '';
k = sort(keys(allow_dir));
if (max_index(k) > 0)
{
  rep = strcat(rep, 'Based on the response to an OPTIONS request :\n\n');
  foreach a (k)
  {
    if (' ' >< a)
       rep = strcat(rep, 
       	   mk_report(start: '  - HTTP methods', blah: a, end: 'are allowed on :'),
	   '\n', allow_dir[a], '\n');
    else
      rep = strcat(rep, '  - HTTP method ', a, ' is allowed on :\n\n', allow_dir[a], '\n');
  }
}

if (tests_all_methods)
{
  inval_meth = make_array();
  k = sort(keys(ok_meth));
  if (max_index(k) > 0)
  {
    rep = strcat(rep, '\nBased on tests of each method : \n\n');
    foreach a (k)
    {
      if (a == all_methods) rep = strcat(rep, 'Any HTTP method is allowed on :\n', ok_meth[a], '\n');
      else    
      {
        dirs = ok_meth[a];
        if (invalid_method >< a)
        {
          inval = 1;
	  a = ereg_replace(string:a, pattern: " *" + invalid_method, replace: "");
        }
        else
          inval = 0;
        
        if (' ' >< a)
          rep = strcat(rep, 
  	    mk_report(start: '  - HTTP methods', blah: a, end: 'are allowed on :'),
	    '\n', dirs, '\n');
        else
          rep = strcat(rep, '  - HTTP method ', a, ' is allowed on :\n\n', dirs, '\n');

        if (inval)
          foreach d (split(dirs, keep: 0))
  	    inval_meth[d] = 1;
      }
    }
    k = sort(keys(inval_meth));
    if (max_index(k) > 0)
    {
      rep = strcat(rep, '  - Invalid/unknown HTTP methods are allowed on :\n\n');
      foreach d (k) rep = strcat(rep, d, '\n');
    }
  }
}

if ( strlen(rep) > 0 )
{
  security_note(port: port, extra: rep);
  if (COMMAND_LINE) display('++++++++ ', port, ' ++++++++\n', rep);
}
