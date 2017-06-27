#
# (C) Tenable Network Security, Inc.
#

# @PREFERENCES@

#
# WEBMIRROR 2.0
#
#
# Written by Renaud Deraison <deraison@nessus.org>
# includes some code by H D Moore <hdmoore@digitaldefense.net>
#
# This plugin mirrors the paths used by a website. We typically care
# to obtain the list of CGIs installed on the remote host, as well as
# the path they are installed under. 
#
# Note that this plugin does not properly check for the syntax of the
# HTML pages returned : it tries to extract as much info as it
# can. We don't care about the pages extensions either (but we do
# case about the mime types)
#
# This plugin takes a really long time to complete, so it updates
# the KB as soon as data is found (as it's likely to be killed
# by nessusd against huge sites)
#
# Features :
#
#  o Directories are added in additions to URIs (ie: if there is a link to /foo/bar/a.gif, then webmirror
#    will crawl /foo/bar/)
#  o Apache and iPlanet directory listing features are used (/foo/bar will be requested as /foo/bar?D=A and
#    /foo/bar/?PageServices)   [thanks to MaXX and/or Nicolas Fischbach for the suggestion]
#  o Content is stored by various keys in the kb, to be easily reused by other scripts
#  o Forms and URIs ending in '?.*' are recognized and a list of CGIs is made from them
#  o Keep-alive support
#
# See also :
#  o torturecgis.nasl
#  o bakfiles.nasl
#  o officefiles.nasl
#
# This is version 2.0 of the plugin - it should be WAY faster and more
# accurate (i wrote a real parser).
#


include("compat.inc");

if(description)
{
 if ( NASL_LEVEL >= 5201 )
  script_id(67257);
 else
  script_id(10662);
 script_version("$Revision: 1.238 $");
 script_cvs_date("$Date: 2014/05/21 22:01:06 $");
 
 if ( NASL_LEVEL >= 5201 )
  script_name(english:"Web mirroring stub");
 else
  script_name(english:"Web mirroring");
 
 script_set_attribute(attribute:"synopsis", value:
"Nessus crawled the remote website." );
 script_set_attribute(attribute:"description", value:
"This script makes a mirror of the remote website(s) and extracts the
list of CGIs that are used by the remote host. 

It is suggested that you change the number of pages to mirror in the
'Options' section of the client." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/05/04");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Performs a quick web mirror");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2014 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 if ( NASL_LEVEL >= 5201 )
  script_dependencie("webmirror3.nbin");
 else
 script_dependencie("find_service1.nasl", "httpver.nasl", "http_login.nasl", "DDI_Directory_Scanner.nasl", "embedded_web_server_detect.nasl", "waf_detection.nbin", "broken_web_server.nasl");
 script_require_ports("Services/www", 80);

 if ( NASL_LEVEL < 5201 )
 {
 script_add_preference(name:"Number of pages to mirror : ",
 			type:"entry",
			value:"1000");

 script_add_preference(name: "Maximum depth : ", type: "entry", value: "6");

# Now a list of pages, seperated by colons
 script_add_preference(name:"Start page : ",
 			type:"entry",
			value:"/");

# server_privileges.php is used by old phpmyadmin (e.g. 2.6.3)
# Crawling this page with the needed credentials and  "follow dynamic pages"
# is dangerous!
 script_add_preference(name: "Excluded items regex :", type: "entry", 
 value: "/server_privileges\.php|logout");
 script_add_preference(name:"Follow dynamic pages : ",
 			type:"checkbox",
			value:"no");
 script_timeout(86400);
 }
 exit(0);
}

if ( NASL_LEVEL >= 5201 ) exit(0, "webmirror3.nbin will run instead");



include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

if ( get_kb_item("Settings/disable_cgi_scanning") &&
     ! get_kb_item("Settings/enable_web_app_tests"))
{
 debug_print('Settings/disable_cgi_scanning=1 and Settings/enable_web_app_tests=0\n');
 exit(0, "Settings/disable_cgi_scanning=1 and Settings/enable_web_app_tests=0");
}

#------------------------------------------------------------------------#

global_var start_page, max_pages, dirs, num_cgi_dirs, max_cgi_dirs, follow_dynamic_pages;
global_var follow_forms, max_depth, excluded_RE;
global_var port, URLs, URLs_hash, MAILTOs_hash, ID_WebServer, Apache, iPlanet;
global_var	URL_depth, URL_ref;
global_var CGIs, Misc, Consoles, Dirs, CGI_Dirs_List, URLs_30x_hash, URLs_auth_hash, Code404;
global_var	URLs_special_headers_hash;
global_var misc_report, cnt, RootPasswordProtected, coffeecup, guardian, SSL_Used;
global_var URL, page, report, foo;
global_var ClearTextPasswordForms, AutoCompletePasswordForms;

global_var	auth_nb, embedded;
global_var	automatic_http_login, http_login, http_pass, http_login_form, http_login_fields, http_login_meth;

global_var	ext_URL_hash, ext_URL_nb, ext_URL_nb_per_host;
global_var	not_a_CGI, req_count;

global_var 	ext_js_cnt;


MAX_URL_LEN = 1024;	# Limit URL length in case the web server is crazy
MAX_EXT_JS_REF = 64;

auth_nb = make_array();
URL_depth = make_array();
ext_js_cnt = make_array();

global_var	MAX_token_nb, MAX_arg_nb, MAX_argval_nb;
MAX_token_nb = 64;
MAX_arg_nb = 512;
MAX_argval_nb = 2048;

######

function try_automatic_login(cgi, args, method, passw)
{
  local_var	e, qs, k, v, a, seen, rq, cookies, u;


  qs = "";
  seen = make_array();

  if (max_index(passw) > 0)
  {
    foreach v (passw)
    {
      qs = strcat(qs, "&", v, "=", urlencode(str: http_pass));
      seen[v] = 1;
    }
  }

  foreach k (keys(args))
  {
    if (seen[k]) continue;
    if (typeof(args[k]) == "array")
      a = args[k];
    else
    {
      if (isnull(args[k])) a = make_list("");
      else a = make_list(args[k]);
    }
    foreach v (a)
    {
      if (v)
      {
        qs = strcat(qs, "&", k, "=", urlencode(str: v));
	break;
      }
    }
    if (! v)
    {
      # Exclude ASP.NET special arguments
      if (k =~ "^__(VIEWSTATE(ENCRYPTED)?|LASTFOCUS|PREVIOUSPAGE|EVENT(VALIDATION|ARGUMENT|TARGET))$")
        qs = strcat(qs, "&", k, "=");
      else
	qs = strcat(qs,  "&", k, "=", urlencode(str: http_login));
    }
  }

  qs = substr(qs, 1);	# Remove first &

  method = toupper(method);
  e = http_form_login(port: port, form: cgi, fields: qs, follow_redirect: 2, save_cookies: 1, method: method);

  if (e == "" || e == "OK")
  {
    # Do not create lists in the KB, that would be toxic
    foreach v (make_list("form", "page", "fields", "meth", "follow_30x"))
      rm_kb_item(name: "www/"+port+"/login_"+v);
    # save...
    http_login_form = cgi;
    http_login_fields = qs;
    http_login_meth = method;
    set_kb_item(name: "www/"+port+"/login_form", value: http_login_form);
    rm_kb_item(name:"www/"+port+"/login_page");	# Unknown => empty
    set_kb_item(name: "www/"+port+"/login_fields", value: http_login_fields);
    set_kb_item(name: "www/"+port+"/login_meth", value: http_login_meth);
    set_kb_item(name: "www/"+port+"/login_follow_30x", value: 2); # Why not?
    set_kb_item(name: "www/"+port+"/automatic_http_login", value: TRUE);
    # Do not try twice, that's useless and dangerous
    automatic_http_login = 0;
    # Get the last request, in case we followed a 30x
    rq = http_last_sent_request();
    rq = split(rq, keep: 0); rq = rq[0];	# Get the first line
    u = eregmatch(string: rq, pattern: '^(GET|POST) +(.*[^ \t]) +HTTP/1\\.[01]$');
    if (! isnull(u)) u = u[2]; else u = cgi;
    
    # Compatibility with old HTTP API
    rq = http_mk_get_req(item: "/", port: port);
    cookies = rq["Cookie"];
    if (cookies)
      set_kb_item(name: string("/tmp/http/auth/", port), value: 'Cookie: '+cookies);
    else
      debug_print("No cookie is set. Old authentication will fail.\n");

    return u;
  }
  return NULL;
}



################ Extract strings from Flash applets ################

function swf_decompress(data)
{
  local_var	len, cm;

  if (data[1] != 'W' && data[2] != 'S') return NULL;

  if (data[0] == 'F')	# Uncompressed
    return data;

  if (data[0] != 'C')
  {
    debug_print("Bad magic ", substr(data, 0, 2), "\n");
    return NULL;
  }

  if (NASL_LEVEL < 3005)
  {
    debug_print('Nessus engine is too old: cannot decompress data\n');
    return NULL;
  }

  if (strlen(data) < 16)
  {
    debug_print("Compressed data is too short\n");
    return NULL;
  }

  # check compression method (8 == deflate)
  cm = ord(data[8]);
  if (cm & 0xF != 8)
  {
    debug_print("CM=", cm, "\n");
    return NULL;
  }
  cm >>>= 4;
  if (cm != 7)
  {
    debug_print("cinfo=", cm, "\n");
    return NULL;
  }

  len = ord(data[4]) + 256 * (ord(data[5]) + 256 * (ord(data[6]) + 256 * ord(data[7])));

  # flg = ord(data[9]);

  return substr(data, 0, 7) + zlib_decompress(data: substr(data, 10), length: len);
}

function swf_extract_strings(s)
{
  local_var	len, i, a, v, str;

  v = make_list(); 
  len = strlen(s);
  for (i = 0; i < len - 1; i ++)
    if (s[i] == '\0')
    {
      str = '';
      for (i = i + 1; i < len; i ++)
      {
        a = ord(s[i]);
	if (a >= 32 && a < 127)
	  str += s[i];
	else
	{
	  if (a == 0)
	  {
	     if (str =~ ".\.(php|asp|cgi|jsp|pl|py|xml|htm|txt)")
	       v[str] = 1;
	     i -= 1;
	  }
          str = NULL;
	  break;
        }
      }
    }
  return keys(v);
}

function swf_fake_html(v)
{
  local_var	u, html;

  if (max_index(v) == 0) return NULL;
  html = '<html>\n<body>\n';
  foreach u (v)
    html = strcat(html, '<a href="', u, '">fake</a>\n');
  return html;
}

#-------------------------------------------------------------------#

function is_in_list(list, item)
{
 local_var i;
 foreach i ( list )
	if ( i == item ) return TRUE;
 return FALSE;
}


function add_cgi_dir(dir)
{
 local_var d, dirs, r, res, u, match;

 if ( num_cgi_dirs >= max_cgi_dirs ) return 0;
 # if (strlen(dir) >= MAX_URL_LEN) return 0;
 if (CGI_Dirs_List[dir]++) return 0;

 u = strcat(dir, "/non-existant-", rand());
 if (! isnull(excluded_RE))
 {
   if (ereg(string: u, pattern: excluded_RE, icase: 1)) return 0;
   if (ereg(string: dir, pattern: excluded_RE, icase: 1)) return 0;
 }

 req_count ++;
 r = http_send_recv3(port: port, method: 'GET', item: u);
 if (isnull(r))
 {
   debug_print('add_cgi_dir: http_send_recv3 ' + build_url(port: port, qs: u) +
    ': ', http_error_msg());
   return NULL;
  }

 if (! ereg(string: r[0], pattern: "^HTTP/[0-9.]+ 404 "))
   return 0;

  dirs = cgi_dirs();
  foreach d (dirs)
  {
  if(d == dir)return(0);
  }

   debug_print(level:2, "Adding ", dir, " as a CGI directory (num#", num_cgi_dirs, "/", max_cgi_dirs, ")\n");
   set_kb_item(name:"/tmp/cgibin", value:dir);
   set_kb_item(name: "www/"+port+"/cgibin", value:dir);
   num_cgi_dirs ++;

# Adds parent directory to cgi_dir 
   while(match = eregmatch(string:dir, pattern:"^(.*)(/[^/]*)$") )
   {
     dir = match[1];
     if(dir != '')
     {
       debug_print(level:2, "Adding ", dir, " as a CGI directory (num#", num_cgi_dirs, "/", max_cgi_dirs, ")\n");
       set_kb_item(name:"/tmp/cgibin", value:dir);
       set_kb_item(name: "www/"+port+"/cgibin", value:dir);
       num_cgi_dirs ++;
     }
   }

   return 1;
}


#--------------------------------------------------------------------------#

function add_30x(url)
{
 if(isnull(URLs_30x_hash[url]))
 {
  debug_print(level:2, "add_30x: ", url);
  set_kb_item(name:string("www/", port, "/content/30x"), value:url);
  URLs_30x_hash[url]++;
 }
}


function add_auth(url, auth)
{
 local_var	v, s, realm, line, n;

 if (strlen(url) == 0) url = '/';
 if (URLs_auth_hash[url]) return;

  set_kb_item(name:string("www/", port, "/content/auth_required"), value:url);
  URLs_auth_hash[url] = 1;
  if(url == "/")RootPasswordProtected = 1;


 foreach line (split(auth, keep: 0))
 {
   v = eregmatch( string: auth, icase: 1,
     pattern: '^WWW-Authenticate: *(Basic|Digest|NTLM|Negociate)( +realm="([^"]*)")?');
   if (! isnull(v))
   {
     s = tolower(v[1]);
     set_kb_item(name: strcat("www/", port, "/authentication_scheme"), value: v[1]);
     realm = v[2];
     n = auth_nb[s];
     if (isnull(n)) n = 0;
     set_kb_item(name: strcat("www/", port, "/content/", s, "_auth/url/", n), value:url);
     if (! isnull(realm))
       set_kb_item(name: strcat("www/", port, "/content/", s, "_auth/realm/", n), value: realm);
     auth_nb[s] = n+1;
    }
  }
}

function add_special_header(url, header)
{
  local_var	i, k;

  # Remove query string
  i = stridx(url, "?");
  if (i > 0) url = substr(url, 0, i - 1);
  header = tolower(header);
  k = header+":"+url;
  if (isnull(URLs_special_headers_hash[k]))
  {
    set_kb_item(name:"www/"+port+"/header/"+header, value:url);
    URLs_special_headers_hash[k] = TRUE;
  }
}


#--------------------------------------------------------------------------#

num_mailto = 0;

function add_mailto(mailto, current)
{
 if ( NASL_LEVEL < 2205 ) return;
 if ( num_mailto > 100 ) return 0;
 mailto = ereg_replace(pattern:"^mailto:([^?]*)(\?.*)?", replace:"\1", string:mailto, icase:TRUE);
 if (strlen(mailto) == 0) return;
 if ( isnull(MAILTOs_hash[mailto]) )
	{
	MAILTOs_hash[mailto] = make_list(current);
	num_mailto++;
	}
  else
	{
	 if ( is_in_list(list:MAILTOs_hash[mailto], item:current) == FALSE )
		MAILTOs_hash[mailto] = make_list(MAILTOs_hash[mailto], current);
	}
  
}

function remember_mailto()
{
 local_var ret;
 local_var mailto, urls, u, n;

 if ( num_mailto == 0 || max_index(keys(MAILTOs_hash)) == 0 ) return NULL;
 foreach mailto (keys(MAILTOs_hash) )
 {
   n = 0;
   set_kb_item(name: "www/"+port+"/mailto", value: mailto);
   foreach u (MAILTOs_hash[mailto])
   {
     set_kb_item(name: "www/"+port+"/mailto/"+mailto+"/"+n, value: u);
     n ++;
   }
 }
     
}

__html_entities = make_array(
"quot",		'"',
"#34", 		'"',
"#39",		"'",
"apos",		"'",
"amp",		"&",
"#38",		"&",
"lt",		"<",
"#60",		"<",
"gt",		">",
"#62",		">"
);

function decode_html_entities(u)
{
  local_var	i, len, u2, j, c, x;

  len = strlen(u);
  u2 = "";
  for (i = 0; i < len; i ++)
  {
    if (u[i] == '%' && substr(u, i+1, i+2) =~ '[0-9A-F][0-9A-F]')
    {
      c = 0;
      for (j = i + 1; j <= i + 2; j ++)
      {
        x = ord(u[j]);
	c *= 16;
        if (x >= 48 && x <= 57) c += x - 48;
        else if (x >= 65 && x <= 70) c += x - 55;
        else if (x >= 97 && x <= 102) c += x - 87;
      }
      if (c >= 33 && c <= 126)	# Printable ASCII
        u2 += raw_string(c);
      else
        u2 += substr(u, i, i+2);
      i += 2; # Loop will add 1;
    }
    else if (u[i] != '&')
      u2 += u[i];
    else
    {
      for (j = i + 1; j < len; j ++)
        if (u[j] !~ '[a-zA-Z]')
	  break;
      if (j >= len || j == i + 1 || u[j] != ';')
      {
        u2 += '&';
      }
      else
      {
        c = __html_entities[substr(u, i+1, j-1)];
	if (isnull(c))
	  u2 += substr(u, i, j);
	else
	  u2 += c;
	i = j;	# loop will add 1
      }
    }
  }
  return u2;
}

function add_url(url, depth, referer)
{
 local_var ext, dir, len;

 # For can_host_php / can_host_asp ...
 if (url =~ '^[^?]+\\.php[3-5]?(\\?.*)?$')
 {
   set_kb_item(name: "www/"+port+"/PHP", value: TRUE);
   set_kb_item(name: "www/PHP", value: TRUE);
 }
 if (url =~ '^[^?]+\\.aspx?(\\?.*)?$')
 {
   set_kb_item(name: "www/"+port+"/ASP", value: TRUE);
   set_kb_item(name: "www/ASP", value: TRUE);
 }
 if (url =~ '^[^?]+\\.jsp(\\?.*)?$')
 {
   set_kb_item(name: "www/"+port+"/JSP", value: TRUE);
   set_kb_item(name: "www/JSP", value: TRUE);
 }
 if (depth > max_depth) return NULL;
 len = strlen(url);
 if (len > MAX_URL_LEN)
 {
   debug_print("add_url(", get_host_name(), ":", port, "): URL is too long (", len , " bytes): ", substr(url, 0, 66), " ...");
   return NULL;
 }
 if (url[0] != '/')
 {
   debug_print('URI is not absolute: ', url);
   return NULL;
 }
 
 if(isnull(URLs_hash[url]))
 {
  debug_print(level: 4, "**** ADD URL ", url, " - referer=", referer, " - depth=", depth, '\n');
  URLs = make_list(URLs, url);
  if (referer) URL_ref[url] = referer;
  URLs_hash[url] = 0;
  if (! isnull(depth)) URL_depth[url] = depth;
   
  url = ereg_replace(string:url,
  			pattern:"([^?]*)\?.*",
			replace:"\1");
			
			
  ext = ereg_replace(pattern:".*\.([^\.]*)$", string:url, replace:"\1");
  if(strlen(ext) && ext[0] != "/" && strlen(ext) < 5 )
  {
   set_kb_item(name:string("www/", port, "/content/extensions/", ext), value:url);
  }
  
  dir = dir(url:url);
  if(dir && !Dirs[dir])
  {
   Dirs[dir] = 1;
   if ( dir !~ "^/manual" ) # Apache
    set_kb_item(name:string("www/", port, "/content/directories"), value:dir);
   if(isnull(URLs_hash[dir]))
   {
    URLs = make_list(URLs, dir);
    if(Apache)URLs  = make_list(URLs,  string(dir, "/?D=A"));
    else if(iPlanet)URLs = make_list(URLs,  string(dir, "/?PageServices"));
    URLs_hash[dir] =  0;
   }
  }
 }
}

function cgi2hash(cgi, base)
{
  local_var	cur_cgi, cur_arg, i, ret, len, v, hn, x;
 
 ret = make_list();
 cur_cgi = ""; 
 len = strlen(cgi);
 for(i = 0; i < len; i ++)
 {
  if (cgi[i] == " " && i+1 < len && cgi[i+1] == "[")
  {
    cur_arg = "";
    for(i = i + 2; i < len; i ++)
    {
      if(cgi[i] == "]")
      {
        cur_cgi = remove_token_from_arg(a: cur_cgi);
	#### Process PHP arrays
	if (base =~ '/(.*\\.(cgi|php[3-5]?))?$')
	{
  	  v = eregmatch(string:cur_cgi, pattern: '^(.*)\\[(.*)\\]$');
	  if (! isnull(v))
	  {
	    if (isnull(hn)) hn = make_array();	# Init
	    if (v[2] == "")
	    {
  	      if (isnull(hn[v[1]])) x = 0; else x = hn[v[1]];
	      cur_cgi = strcat(v[1], '[', x, ']');
	      debug_print(level:2, 'cgi2hash: cgi="', cgi, '" ', v[1], '[', v[2], '] --> ', cur_cgi);
	      x ++;
	      hn[v[1]] = x;
	    }
	    else if (v[2] =~ '^[0-9]+$')
	    {
	      hn[v[1]] = int(v[2]);
	    }
	  }
	}
	####
        ret[cur_cgi] = cur_arg;
	cur_cgi = "";
	cur_arg = "";
	if (i + 2 >= len)
	{
	 return ret;
	}
	i += 2;
	break;
      }
      else cur_arg += cgi[i];
    }
  }
  cur_cgi += cgi[i];
 } 
 return ret;
}

function hash2cgi(hash)
{
 local_var ret, h;
 
 ret = "";
 foreach h (keys(hash))
 {
  ret += string(h, " [", hash[h], "] ");
 }
 return ret;
}


function remove_token_from_arg(a)
{
  local_var	v, tk, tklen, tknam;

  while(1)
  {
    v = eregmatch(string: a, pattern: "^(.*[^a-fA-F0-9])?([0-9A-F]{32}|[0-9A-F]{40}|[0-9A-F]{64}|[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})([^a-fA-F0-9].*)?$");
    if (isnull(v)) return a;
    tk = v[2];
    tklen = 4 * strlen(tk);
    tknam = strcat("$", tklen, "BITS$");
    a = strcat(v[1], tknam, v[3]);
    if (-- MAX_token_nb >= 0)
    {
      set_kb_item(name: "www/"+port+"/token"+tklen, value: tk);
      debug_print(level: 3, "Token: ", tk);
    }
  }
  # NOTREACHED
}


global_var	SEEN_cgi_arg, SEEN_cgi_arg_val;

SEEN_cgi_arg = make_array();
SEEN_cgi_arg_val = make_array();

function clean_cgi_name(cgi)
{
  local_var	z;

  # Clean remains of Javascript
  if (experimental_scripts)
    while ('+' >< cgi)
    {
      z = eregmatch(string: cgi, pattern: "([^']*)' *\+ *'(.*)");
      if (isnull(z)) break;
      cgi = strcat(z[1], z[2]);
    }

  if ('//' >< cgi)
    repeat
    {
      z = cgi;
      cgi = str_replace(string: cgi, find: '//', replace: '/');
    }
    until (z == cgi);

  return cgi;
}

function remember_arg_val(cgi, arg, val)
{
  local_var	k;

  if (MAX_arg_nb < 0)
  {
    debug_print("Too many arguments on port ", port, " CGI ", cgi);
    return;
  }

  if (isnt_a_CGI(cgi: cgi, args: arg+' ['+val+']')) return;

  k = strcat(cgi, '\n', arg);
  if (! SEEN_cgi_arg[k])
  {
    set_kb_item(name: strcat("www/", port, "/cgi-arg", cgi), value: arg);
    SEEN_cgi_arg[k] = 1;
    MAX_arg_nb --;
  }

  if (MAX_argval_nb < 0)
  {
    debug_print("Too many argument values on port ", port, " CGI ", cgi);
    return;
  }

  k = strcat(cgi, '\n', arg, '\n', val);
  if (! SEEN_cgi_arg_val[k])
  {
    set_kb_item(name: strcat("www/", port, "/cgi-params", cgi, "/", arg), value: val);
    SEEN_cgi_arg_val[k] = 1;
    MAX_argval_nb --;
  }
  debug_print(level: 2, "CGI: ", cgi, " ARG: ", arg, " VAL: ", val);
}


function isnt_a_CGI(cgi, args, args_h)
{
  local_var	l, args_l, a, v, k, flag;

  if (not_a_CGI[cgi])
  {
    debug_print(level:2, "isnt_a_CGI - directory index? ", cgi);
    return 1;
  }

  # make sure the URL contains valid chars
  if (cgi !~ "^[A-Za-z0-9-_.~!*'();:@&=+$,/?%#[\]]+$")
    return 1;

  l = strlen(cgi);

  if (l > 0 && cgi[l-1] == "/")
  {
    if (! isnull(args))
    {
      if (ereg(string: args, pattern: "^C=[NMSD](;O)? \[[AD]\] *$", icase: FALSE) ||
	  ereg(string: args, pattern: "^C \[[NMSD](;O=[AD])?\] *$", icase: FALSE))
      {
        debug_print(level:2, "isnt_a_CGI: Apache auto-index: ", cgi, "?", args);
        return 1;
      }
    }
    if (! isnull(args_h))
    {
      args_l = keys(args_h);
      if (max_index(args_l) > 0)
      {
        flag = 1;
	foreach a (args_l)
	{
	  v = args[a];
	  if (typeof(v) != "array") v = NULL;
	  if (a == "C")
	  {
	    if (isnull(v)) flag = 0;
	    else
	      foreach k (v)
	        if (k !~ "^[NMSD]")
		{
		  flag = 0; break;
		}
	  }
	  else if (a == "O")
	  {
	    if (isnull(v)) flag = 0;
	    else
	      foreach k (v)
	        if (k !~ "^[AD]")
		{
		  flag = 0; break;
		}
	  }
	  else
	    flag = 0;
	  if (! flag) break;
	}
        if (flag)
        {
          debug_print(level:2, "isnt_a_CGI: Apache auto-index: ", cgi, "?", args);
          return 1;
        }
      }
    }
  }

  return 0;
}

function forget_CGI(cgi)
{
  local_var	l, k, a;

  k = "www/"+port+"/cgi-arg"+cgi;
  l = get_kb_list(k);
  rm_kb_item(name: k);
  if (! isnull(l))
    foreach a (l)
      rm_kb_item(name: "www/"+port+"/cgi-params"+cgi+"/"+a);
  rm_kb_item(name: "www/"+port+"/cgi", value: cgi);

}

function add_cgi(cgi, args, form, method, referer, enctype)
{
 local_var mydir, tmp, a, new_args, common, c, l;

 if (isnull(cgi))
 {
   err_print("add_cgi: missing argument cgi");
   return NULL;
 }

 cgi = clean_cgi_name(cgi: cgi);
 args = string(args);

 if (isnt_a_CGI(cgi:cgi, args: args)) return;

 new_args = cgi2hash(cgi:args, base: cgi);
 common = make_list();
 if (form)
 {
   form = clean_cgi_name(cgi: form);
   set_kb_item(name: strcat("www/", port, "/form-action", cgi), value: form);
 }
 if (method)
   set_kb_item(name: strcat("www/", port, "/form-method", cgi), value: tolower(method));
 else
   set_kb_item(name: strcat("www/", port, "/form-method", cgi), value: 'get');

 if (referer)
   set_kb_item(name: strcat("www/", port, "/form-referer", cgi), value: referer);
 if (enctype)
   set_kb_item(name: strcat("www/", port, "/form-enctype", cgi), value: tolower(enctype));
 set_kb_item(name: strcat("www/", port, "/cgi"), value: cgi);

 foreach c (keys(new_args))
 {
   if(isnull(common[c]))common[c] = new_args[c];
   remember_arg_val(cgi: cgi, arg: c, val: new_args[c]);
  }
 if(isnull(CGIs[cgi]))
 {
  debug_print(level:2, ">>> ADDING CGI ",cgi, " form=", form, " args=", args, "\n");
  CGIs[cgi] = args;
  mydir = dir(url:cgi);
  if (mydir) add_cgi_dir(dir:mydir);
 }
 else
 {
    debug_print(level:2, ">>> ADD CGI ",cgi, " form=", form, " args=", args, "\n");
    if (form)
      tmp = cgi2hash(cgi:CGIs[cgi], base: form);
    else
      tmp = cgi2hash(cgi:CGIs[cgi], base: cgi);

    foreach c (keys(tmp))
    {
     common[c] = tmp[c];
    }
    
    CGIs[cgi] = hash2cgi(hash:common);
    }
}

function add_arg_to_cgi(cgi, param, val, form)
{
  if (isnull(cgi))
  {
    err_print("add_arg_to_cgi: missing argument cgi");
    return NULL;
  }
  cgi = clean_cgi_name(cgi: cgi);
  if (isnt_a_CGI(cgi: cgi, args: val)) return;
  if (form)
  {
    form = clean_cgi_name(cgi: form);
    set_kb_item(name: strcat("www/", port, "/form-action", cgi), value: form);
  }
  set_kb_item(name: strcat("www/", port, "/cgi"), value: cgi);
  param = remove_token_from_arg(a: param);
  remember_arg_val(cgi: cgi, arg: param, val: val);
}

function add_cgi_args_from_hash(cgi, args, form, method, passw, enctype)
{
  local_var	k, a, v, u;

  debug_print(level:2, "add_cgi_args_from_hash: cgi=", cgi, " form=", form, " method=", method);

  if (isnull(cgi))
  {
    err_print("add_cgi_args_from_hash: missing argument cgi");
    return NULL;
  }

  cgi = clean_cgi_name(cgi: cgi);
  if (isnt_a_CGI(cgi: cgi, args_h: args)) return;

  if (form)
  {
    form = clean_cgi_name(cgi: form);
    set_kb_item(name: strcat("www/", port, "/form-action", cgi), value: form);
  }
  if (method)
    set_kb_item(name: strcat("www/", port, "/form-method", cgi), value: tolower(method));
  else
    set_kb_item(name: strcat("www/", port, "/form-method", cgi), value: 'get');

  if (enctype)
    set_kb_item(name: strcat("www/", port, "/form-enctype", cgi), value: enctype);
  set_kb_item(name: strcat("www/", port, "/cgi"), value: cgi);

  foreach k (keys(args))
  {
    if (typeof(args[k]) == "array")
      a = args[k];
    else
    {
      if (isnull(args[k])) a = make_list("");
      else a = make_list(args[k]);
    }
    k = remove_token_from_arg(a: k);
    foreach v (a)
    {
      if (isnull(v)) v = "";
      remember_arg_val(cgi: cgi, arg: k, val: v);
    }
  }

  if (max_index(passw) > 0)
  {
    set_kb_item(name: strcat("www/", port, "/password-form"), value:cgi);
    k = strcat("www/", port, "/password-params/", cgi);
    foreach v (passw)
    {
      set_kb_item(name: k, value:v);
      debug_print(level: 3, "port=", port, " cgi=", cgi, " passw=", v);
    }
    if (automatic_http_login)
    {
      u = try_automatic_login(cgi: cgi, args: args, method:method, passw:passw);
      if (u)
      {
        URLs = make_list(URLs, u);
	URLs_hash[u] = 0;
      }
    }
  }
}


#---------------------------------------------------------------------------#

function dir(url)
{
  local_var	v;

  # Do not store any JavaScript piece of code into the KB:
  ## Truncate the query string,
  ## Make sure that the item starts with a /
  #
  # NB: this function will return NULL if url=="/"; this is correct!
  
  v = eregmatch(string: url, pattern: "^(/[^?#]*)(/[^/#]*|\?.*)$");
  if (isnull(v)) return NULL;
  return v[1];
}

function remove_dots(url)
{
 local_var	old, len;

 while (strlen(url) > 2 && substr(url, 0, 1) == "./") url = substr(url, 2);

 url = str_replace(string: url, find: "/./", replace: "/");
 repeat
 {
   old = url;
   len = strlen(url);
    if (len > 2 && substr(url, len - 2) == "/.") url = substr(url, 0, len -3);
 }
 until (old == url);

 repeat
 {
   old = url;
   url = ereg_replace(string: url, pattern: "([^/.]|\.[^/.])+/+\.\./+", replace: "");
 }
 until (old == url);
 return url;  
}

function remove_cgi_arguments(url, current)
{
 local_var idx, idx2, cgi, cgi_args, args, arg, a, b, v;
 local_var idx3;

 if (strlen(url) > MAX_URL_LEN)
 {
   debug_print("remove_cgi_arguments(", get_host_name(), ":", port, "): URL is too long: ", substr(url, 0, 63), " ...");
   return NULL;
 }

 debug_print(level: 2, "***** remove_cgi_arguments '", url, "\n");

 # Remove the trailing blanks
 url = ereg_replace(string: url, pattern: '^(.*[^ \t])[ \t]+$', replace: "\1");

 idx = stridx(url, "?");
 idx2 = stridx(url, ";");
 if ( idx2 > 0 && idx2 < idx ) idx3 = idx2;
 else idx3 = idx;

 if(idx3 < 0)
   return remove_dots(url: url);
 else 
   if(idx >= strlen(url) - 1)
 {
  cgi = remove_dots(url: substr(url, 0, strlen(url) - 2));
  add_cgi(cgi:cgi, args:"", referer: current);
  return cgi;
 }
 else
 {
  if(idx3 > 0) cgi = substr(url, 0, idx3 - 1);
  else cgi = ".";	# we should not come here
  
  #
  # Avoid Apache's directories indexes
  #
  if (isnt_a_CGI(cgi: cgi, args: substr(url, idx + 1))) return NULL;

  cgi_args = split(substr(url, idx + 1, strlen(url) - 1), sep:"&", keep:0);

  foreach arg (make_list(cgi_args)) 
  {
   # arg = arg - "&"; arg = arg - "amp;";
   v = eregmatch(string: arg, pattern: "([^=]+)=(.*)");
   if (! isnull(v))
   {
     args = string(args, v[1] , " [", v[2], "] ");
     add_arg_to_cgi(cgi:cgi, param: v[1], val: v[2]);
   }
   else
   {
     args = string(args, arg, " [] ");
     add_arg_to_cgi(cgi:cgi, param: arg, val: "");
   }
  }
  add_cgi(cgi:cgi, args:args, referer: current);
  if ( follow_dynamic_pages )
   return url;
  else
   return cgi;
 }
}


function basename(name, level)
{
 local_var i;
 
 if(strlen(name) == 0)
  return NULL;
  
  for(i = strlen(name) - 1; i >= 0 ; i --)
  {
   if(name[i] == "/")
   {
    level --;
    if(level < 0)
    { 
     return(substr(name, 0, i));
    }
   }
 }
 
 # Level is too high, we return /
 return "/";
}


function remove_double_slash(url)
{
  local_var	idx, a, b;

  idx = stridx(url, "?");
  if (idx == 0)
    return url;
  else if (idx < 0)
  {
    a = url; b = NULL;
  }
  else
  {
    if (idx > 0)
      a = substr(url, 0, idx - 1);
    else
      a = "";
    b = substr(url, idx + 1);
  }
  a = ereg_replace(string: a, pattern: "//+", replace: "/");
  if (isnull(b)) return a;
  else
    return strcat(a, "?", b);
}

global_var	same_hosts_l;
same_hosts_l = make_array();

function _wm_same_host(h)
{
 local_var	n, i;
 n = tolower(get_host_name());
 # This is not true, but we want to follow links to localhost
 if (h == "localhost" || h =~ "^127\.[0-9]+\.[0-9]+\.[0-9]$") return 1;
 if (n == h) return 1;
 i = get_host_ip();
 if (i == h) return 1;

 # Do not call same_host, it was broken
 return 0;
}

function wm_same_host(h)
{
 h = tolower(h);
 if (same_hosts_l[h] == 'y') return 1;
 if (same_hosts_l[h] == 'n') return 0;
 set_kb_item(name:"webmirror/"+port+"/hosts", value: h);
 if (_wm_same_host(h: h))
 {
  same_hosts_l[h] = 'y';
  return 1;
 }
 else
 {
  same_hosts_l[h] = 'n';
  return 0;
 }
}


function canonical_url(url, current)
{
  local_var	u;

  u = _canonical_url(url:url, current:current);
  if (isnull(u)) return NULL;
  return sanitize_url(u: u);
}

function _canonical_url(url, current)
{
 local_var num_dots, i, location, port2, e, redir, len;

 url = decode_html_entities(u: url);
 debug_print(level: 2, "***** canonical '", url, "' (current:", current, ")\n");
 
 len = strlen(url);
 if(len == 0)
  return NULL;
 if (len > MAX_URL_LEN)
 {
   debug_print(level: 1, 'canonical_url: length(url)=', len);
   return NULL;
 }
  
 if(url[0] == "#")
  return NULL;

 if ('\r' >< url || '\n' >< url)
 {
   debug_print(level: 1, 'canonical_url: url contains \\r or \\n: ', url);
   return NULL;
 }

 i = stridx(current, "?");
 if (i == 0)
  current = "";
 else if (i > 0)
  current = substr(current, 0, i - 1);

 # Links like <a href="?arg=val">xxx</a> 
 if (url[0] == '?')
 {
    url = strcat(current, url);
 }
 
 i = stridx(url, "#");
 if (i == 0)
   url = "";
 else if (i > 0)
   url = substr(url, 0, i - 1);
 
 if(url == "./" || url == ".")
   return current;
 
 debug_print(level: 3, "**** canonical(again) ", url, "\n");
 
 if(ereg(pattern:"^[a-z]+:", string:url, icase:TRUE))
 {
  e = eregmatch(string:url, pattern:"^(https?)://([^/:?]+)(:[0-9]+)?([/?].*)?$", icase: TRUE);
  if(! isnull(e))
  {
   if (SSL_Used && strlen(e[1]) < 5)	# HTTP
   {
     add_ext_URL(u: url, proto: e[1], host: e[2], current: current);
     return NULL;
   }
   if (isnull(e[3]))
     if (strlen(e[1]) == 5)	# https
       port2 = 443;
     else
       port2 = 80;
   else
     port2 = int(substr(e[3], 1));
   location = e[2];
   debug_print(level: 4, ">> ", e[1], "://", location, ":", port2, e[4]);

   if (port != port2) 
   {
     # add_ext_URL(u: url, proto: e[1], host: e[2], current: current);
     return NULL;
   }
   if (! wm_same_host(h: location))
   {
     add_ext_URL(u: url, current: current);
     return NULL;
   }

   redir = e[4];
   if (redir == "") redir = "/";
   else if (redir[0] != "/") redir = strcat("/", redir);
   return remove_cgi_arguments(url: redir, current: current);
  }
  else if ( ereg(pattern:"^mailto:[a-z0-9_.-]+@[a-z0-9_.-]+\.[a-z0-9.-]+", string:url, icase:TRUE) )
  {
	add_mailto(mailto:url, current:current);
  }
  else
    add_ext_URL(u: url, current: current);
 }
 else
 {
   url = remove_double_slash(url: url);
   debug_print(level: 3, "***** canonical '", url, "' (after remove_double_slash)");

   if(url == "/")  return "/";

 if(url[0] == "/")
  return remove_cgi_arguments(url:url, current: current);
 else
 {
  i = 0;
  num_dots = 0;
 
  while (strlen(url) > 0 && url[0] == " ") url = substr(url, 1);
  while(strlen(url) > 2 && substr(url, 0, 2) == "../")
  {
   num_dots ++;
   url = substr(url, 3);
   if (isnull(url)) url = "";
  }
  
  while(strlen(url) > 1 && substr(url, 0, 1) == "./")
  {
    url = substr(url, 2);
    if (isnull(url)) url = "";
  }

  debug_print(level: 3, "***** canonical '", url, "' (after .. removal)");

  url = string(basename(name:current, level:num_dots), url);
 }

 if(url[0] != "/")
 	return remove_cgi_arguments(url:string("/", url), current: current);
 else
 	return remove_cgi_arguments(url:url, current: current);
 }
 return NULL;
}



#--------------------------------------------------------------------#

 
function extract_location(loc, page, depth, referer)
{
 local_var url;
 
 debug_print(level: 3, '***** extract_location ', loc, ' - depth=', depth, '\n'); 
 
 if(!loc) return NULL;

 # loc = chomp(loc);

 # The current page is necessary to follow relative redirections (even if they
 # are not allowed by the RFCs!)
 url = canonical_url(url:loc, current: page); 
 if( url )
 {
   if (ereg(string: url, pattern: excluded_RE, icase: 1)) return NULL;

   add_url(url : url, depth:depth+1, referer: referer);
   return url;
  }

  return NULL;
}


_special_html_char = make_array(
# '<',	'%3C',	# Do like Firefox
# '>',	'%3E',	# Do like Firefox
'\t',	'%09',
'\n',	'%0A',
'\r',	'%0D',
'\f',	'%0C',
 ' ',	'%20' );

function sanitize_url(u)
{
  local_var	idx, p, qs, c;

  idx = stridx(u, '?');
  if (idx == 0)
    return u;
  if (idx < 0)
    p = u;
  else
  {
    p = substr(u, 0, idx - 1);
    qs = substr(u, idx);
  }
  foreach c (keys(_special_html_char))
    p = str_replace(string: p, find: c, replace: _special_html_char[c]);
  while ('//' >< p)
    p = str_replace(string: p, find: '//', replace: '/');
  if (idx < 0) return p;
  return strcat(p, qs);
  
}

function retr(port, page, referer, depth)
{
 local_var	r, q, harray, code, resp, headers, u, swf, v, h;

 if (depth >= max_depth) return NULL;
 debug_print(level: 2, "retr: port=", port, " page=", page, " referer=", referer, " depth=", depth);

 if (page[0] != '/')
 {
   debug_print('URI is not absolute: ', page);
   return NULL;
 }

 headers = NULL;
 if (referer)
  headers = make_array("Referer", build_url(port: port, qs: referer));
 req_count ++;
 r = http_send_recv3( port: port, method: 'GET', item: page, 
     		      add_headers: headers,
		      only_content: 'application/x-shockwave-flash|text/(xml|html)');
 if (isnull(r))
 {
   debug_print("Web server is dead? port=", port, "; page=", page, ' : ', 
     http_error_msg());
   # Do not exit at once, it would disrupt the crawler on a temporary glitch
   return NULL; # No web server
 }

 debug_print(level: 4, '*** RETR page=', page, ' - referer=', referer, ' - response=', r[0], '\n');

 # if (strlen(resp) < 12 ) return NULL;
 harray = parse_http_headers(status_line: r[0], headers: r[1]);
 # If the headers are corrupted, try to disable Keep-Alive
 if (harray['$errors'] )
 {
   debug_print('retr(port=', port, ', page=', page, ') : errors while parsing headers - trying to disable keep-alive.');
   http_disable_keep_alive();
 }
 #
 code = harray['$code'];
 if(code != 200)
 {
  if(code == 401 || code == 403 )
     {
# Do not use harray['www-authenticate'], there could be several 
# WWW-Authenticate headers
      add_auth(url:page, auth: egrep(string: r[1], pattern: '^WWW-Authenticate:', icase: 1));
      http_reauthenticate_if_needed(port: port);
      return NULL;
     }
# 301 Moved Permanently  (should keep the same method)
# 302 Found 		 (temporary; should keep the same method)
# 303 See Other		 (switch to GET)
# 307 Temporary Redirect (keep the same method)
  if (code == 301 || code == 302 || code == 303 || code == 307)
  { 
   q = harray["location"];

   # if a page redirects to itself, try to follow it up to five times
   if (q == page && URLs_30x_hash[page] < 5)
     URLs_hash[page] = NULL;  # act like we haven't seen this page yet

   add_30x(url:page);
   
   # Don't echo back what we added ourselves...
   if(!(("?PageServices" >< page || "?D=A" >< page) && ("?PageServices" >< q || "?D=A" >< q)))
   	extract_location(loc: q, page: page, depth: depth, referer: referer);
   http_reauthenticate_if_needed(port: port);
   return NULL;
  }
 }
 
 if ( ! ID_WebServer )
 {
 if ( "Apache" >< harray["server"] ) Apache ++;
 else if ( "Netscape" >< harray["server"] ) iPlanet ++;
 ID_WebServer ++;
 }

 foreach h (make_list("X-Frame-Options", "X-Content-Security-Policy", "Origin"))
 {
   if (egrep(string:r[1], pattern:"^"+h+":", icase: 1))
     add_special_header(url:page, header:h);
 }

 if (harray["content-type"] && harray["content-type"] =~ "application/x-shockwave-flash")
 {
   swf = swf_decompress(data: r[2]);
   if (isnull(swf)) return NULL;
   v = swf_extract_strings(s: swf); swf = NULL;
   return swf_fake_html(v: v);
 }
 else if(harray["content-type"] && harray["content-type"] !~ "text/(xml|html)")
   return NULL;
 else 
 {
    resp = r[2];
    if (!resp) return NULL; # Broken web server ?
    debug_print(level: 4, '\n----------------\n', r[2],'\n----------------\n\n' );
    resp = str_replace(string:resp, find: '\r', replace:" ");
    resp = str_replace(string:resp, find: '\n', replace:" ");
    resp = str_replace(string:resp, find: '\t', replace:" ");
    return resp;
  }
}

#---------------------------------------------------------------------------#


function token_split(content)
{
 local_var i, j, k, str;
 local_var ret, len, num;
 local_var in_script;

 local_var n;
 local_var array;
 local_var pos;


 
 num = 0;
 
 n = 0;
 
 ret = make_list();
 pos = make_list();
 array = make_list();
 len = strlen(content);
 
 for (i=0;i<len;i++)
 {
  if(((i + 3) < len) && content[i]=="<" && content[i+1]=="!" && content[i+2]=="-" && content[i+3]=="-" && in_script == FALSE )
  {
   j = stridx(content, "-->", i);
   if( j < 0) break;
   i = j;
  }
 else  
  if(content[i]=="<")
  {
   str = "";
   i ++;
   
   while(i < len && content[i] == " ")i ++;
   
   for(j = i; j < len ; j++)
   {
    if(content[j] == '"')
    {
      k = stridx(content, '"', j + 1);
      if(k < 0){
	array[0] = ret;
  	array[1] = pos;
      	return(array); # bad page
	}
      str = str + substr(content, j, k);
      j = k;
    }
    else if(content[j] == '>')
    {        
     if(ereg(pattern:"^(a|area|frame|meta|iframe|link|img|form|/form|input|button|textarea|select|/select|applet|option|script|embed|/script)( .*|$)", string:str, icase:TRUE))
     	{
	if ( ereg(pattern:"^script", string:str, icase:TRUE)  ) in_script = TRUE;
	else if ( ereg(pattern:"^/script", string:str, icase:TRUE)  ) in_script = FALSE;
        num ++;
     	ret[n] = str;
	pos[n] = j;
	n++;
        if ( num > 5000 ) 
	{
	 array[0] = ret;
  	 array[1] = pos;
      	 return(array); # bad page
	}
	}
     break;
    }
    else str = str + content[j];
   }
   i = j;
  }
 }
 

 array[0] = ret;
 array[1] = pos;
 return(array); 
}



function token_parse(token, position)
{
 local_var ret, i, j, len, current_word, word_index, current_value, char;
 
 
 ret = make_array();
 len = strlen(token);
 current_word = "";
 word_index = 0;
 
 for( i = 0 ; i < len ; i ++)
 {
  if(token[i] == " "|| token[i] == '\t' || token[i] == "=" )
  {
   while(i+1 < len && (token[i+1] == " " || token[i+1] == '\t') )i ++;
   if(i >= len)break;
   
   if(word_index == 0)
   {
    ret["nasl_token_type"] = tolower(current_word);
    ret["nasl_token_position"] = position + i;
   }
   else
   {
    while(i+1 < len && token[i] == " ")i ++;
    if(token[i] != "=")
    {
    	 ret[tolower(current_word)] = NULL; 
    }
    else
    {
    	i++;
        while(i+1 < len && token[i] == " ")i ++;
	char = NULL;
	if(i >= len)break;
    	if(token[i] == '"')char = '"';
	else if(token[i] == "'")char = "'";
	
	if(!isnull(char))
 	{
	 j = stridx(token, char, i + 1);
	 if(j < 0)
	  {
          debug_print('token_parse: PARSE ERROR 1\n');
	  return(ret); # Parse error
	  }
	 ret[tolower(current_word)] = substr(token, i + 1, j - 1);
	 while(j+1 < len &&  token[j+1]==" ")j++;
	 i = j;
	}
        else
        {
         j = stridx(token, ' ', i + 1);
	 if(j < 0)
	  {
	   j = strlen(token);
	  }
	 ret[tolower(current_word)] = substr(token, i, j - 1);
	 i = j;
       }
     }
   }
    current_word = "";
    word_index ++;
  }
  else {
        # Filter out non-ascii text 
  	if(i < len && ord(token[i]) < 0x7e && ord(token[i]) > 0x21 )current_word = current_word + token[i];

	# Too long token
	if ( strlen(current_word) > 64 ) return ret;
	}
 }
 
 if(!word_index) {
	ret["nasl_token_type"] = tolower(current_word);
    	ret["nasl_token_position"] = position;
 }
	
 return ret;
}


#-------------------------------------------------------------------------#

function parse_java(elements) 
{
    local_var archive, code, codebase;

    archive = elements["archive"];
    code = elements["code"];
    codebase = elements["codebase"];

    if (codebase) 
    {
         if (archive)
            set_kb_item(name:string("www/", port, "/java_classfile"), value:string(codebase,"/",archive));
         if (code)
             set_kb_item(name:string("www/", port, "/java_classfile"), value:string(codebase,"/",code));
    } 
    else 
    {
         if (archive)
            set_kb_item(name:string("www/", port, "/java_classfile"), value:archive);
         if (code)
            set_kb_item(name:string("www/", port, "/java_classfile"), value:code);
    }
}







function parse_javascript(elements, current, depth, src)
{
  local_var url, pat, array;
  local_var idx, i, n;
  local_var in_call, in_quote, in_doublequote;
  local_var srcLw, p, j, par, str_only;


  if ( isnull(src) ) src = elements["onclick"];
  n = strlen(src); srcLw = tolower(src);

  while ( TRUE )
  {
   idx = n;
   foreach p (make_list("window.open", "window.location", "document.location"))
   {
     j = stridx(srcLw, p, i);
     if (j >= 0 && j < idx)
     {
       idx = j;
       pat = p;
     }
   }
   if ( idx >= n ) break;
   str_only = (p != "window.open");
   in_call = FALSE;
   in_quote = FALSE;
   url = "";
   for ( i = idx + strlen(pat) ; i < n ; i ++ )
   {
     if ( in_call == FALSE )
     {
      if ( src[i] == '\n' || src[i] == '\r' || src[i] == ' ' || src[i] == '\t' ) continue;
      if (str_only)
      {
        if ( src[i] == '=' ) in_call = TRUE;
      }
      else
      {
        if ( src[i] == '(' ) in_call = TRUE;
      }
     }
     else
     {
      if (src[i] == '\\') i ++;
      else if ( src[i] == '\'' && !in_quote ) in_quote = TRUE;
      if (src[i] == '"' && !in_doublequote) in_doublequote = TRUE;
      else if ( src[i] == '\'' && in_quote) { in_quote = FALSE; break ; }
      else if ( src[i] == '"' && in_doublequote ) { in_doublequote = FALSE; break; }
      else if ( src[i] == ')' && ! str_only && in_quote == FALSE && in_doublequote == FALSE)
      {
		in_call = FALSE;
      }
      else if ( src[i] == ';' && str_only && in_quote == FALSE && in_doublequote == FALSE)
      {
		in_call = FALSE;
      }
      else
      {
        url += src[i];
      }
     }
   }
   url = canonical_url(url:url, current:current); 
   if( url ) add_url(url : url, depth: depth+1, referer: current);
 }
}

function parse_javascript_src(elements, current, depth)
{
  local_var	v, s;

  if ( isnull(elements["src"]) ) return;
  v = strcat("page: ", current, " link: ", elements["src"]);
  if ( ext_js_cnt[port] < MAX_EXT_JS_REF )
  {
   set_kb_item(name: strcat("www/", port, "/external_javascript"), value: v);
   ext_js_cnt[port] ++;
  } 

  s = canonical_url(url: elements["src"], current: current);
  if (s) add_url(url: s, depth: depth + 1, referer: current);
  
  if ( ereg(pattern:"^http://([a-z]*\.)?(uc8010|ucmal)\.com/", string:elements["src"], icase:TRUE) )
  { 
   set_kb_item(name:string("www/", port, "/infected/pages"), value: v);
  }
  else if ( ereg(pattern:"^http://([a-z*]\.)?nihaorr1\.com/", string:elements["src"], icase:TRUE) )
  {
   set_kb_item(name:string("www/", port, "/infected/pages"), value: v);
  }
  # Lizamoon
  else if (ereg(pattern:"^http://([a-z.0-9-]+)/ur\.php$", string:elements["src"], icase:TRUE))
  {
   set_kb_item(name: "www/"+port+"/infected/pages", value: v);
  }
  # http://blog.armorize.com/2011/10/httpjjghuicomurchinjs-mass-infection.html
  # http://www.zdnet.com/blog/security/over-a-million-web-sites-affected-in-mass-sql-injection-attack/9662
  else if (ereg(pattern:"^http://(nbnjk[il]|jjghui)\.com/urchin\.js$", string:elements["src"], icase:TRUE))
  {
   set_kb_item(name: "www/"+port+"/infected/pages", value: v);
  }
  # http://isc.sans.edu/diary.html?storyid=12127
  # http://isc.sans.edu/diary.html?storyid=12304
  # http://isc.sans.edu/diary.html?storyid=13813
  # http://isc.sans.edu/diary.html?storyid=13864
  else if (ereg(pattern:"^http://(lilupophilupop\.com|lasimp04risoned\.rr\.nu|eighbo02rsbarr\.rr\.nu|reque83ntlyin\.rr\.nu|tentsf05luxfig\.rr\.nu|andsto57cksstar\.rr\.nu|brown74emphas\.rr\.nu|tartis78tscolla\.rr\.nu|senior78custome\.rr\.nu|sfl20ewwa\.rr\.nu|ksstar\.rr\.nu|enswdzq112aazz\.com|www\.bldked98f5\.com|www1\.mainglobilisi\.com|xinthesidersdown\.com|inglon03grange\.rr\.nu|senior78custome\.rr\.nu)/sl\.php$", string:elements["src"], icase:TRUE))
  {
   set_kb_item(name: "www/"+port+"/infected/pages", value: v);
  }
  # http://isc.sans.edu/diary.html?storyid=13036
  else if (ereg(pattern:"^http://(nikjju|hgbyju)\.com/r\.php$", string:elements["src"], icase:TRUE))
  {
   set_kb_item(name: "www/"+port+"/infected/pages", value: v);
  }
}


function parse_dir_from_src(elements, current)
{
 local_var src, dir;
 
 src = elements["src"];
 if( ! src ) return NULL;
 
 src = canonical_url(url:src, current:current);
 dir = dir(url:src);
 if(dir && !Dirs[dir])
 {
  Dirs[dir] = 1;
  if ( dir !~ "/manual" ) # Apache
   set_kb_item(name:string("www/", port, "/content/directories"), value:dir);
  if(isnull(URLs_hash[dir]))
   {
    URLs = make_list(URLs, dir);
    URLs_hash[dir] =  0;
   }
  }
}


function parse_href_or_src(elements, current, depth)
{
 local_var href;

 debug_print(level: 4, "***** parse_href_or_src href=", elements["href"], " src=", elements["src"], '\n');

 if (elements['rel'] = 'stylesheet' && elements['type'] == 'text/css')
 {
   return NULL;
 }

 href = elements["href"];
 if(!href)href = elements["src"];
 
 if(!href){
	return NULL;
	}
 
 href = canonical_url(url:href, current:current);
 if( href )
 {
  add_url(url: href, depth: depth+1, referer: current);
  return href;
 }
 return NULL;
}

function parse_embed(elements, current, depth)
{
  local_var	src;
 
  debug_print(level: 4, "***** parse_embed=", elements["embed"], " src=", elements["src"], '\n');
 
  src = elements["src"];
  if (! src) return NULL;
  src = canonical_url(url: src, current: current);
  add_url(url: src, depth: depth+1, referer: current);
  return src;
}

function parse_refresh(elements, current, depth)
{
 local_var href, content, t, sub;
 
 content = elements["content"];
 
 if(!content)
  return NULL;
 t = strstr(content, ";");
 if( t != NULL ) content = substr(t, 1, strlen(t) - 1);
 
 content = string("a ", content);
 sub = token_parse(token:content, position:0);
 
 if(isnull(sub)) return NULL;
 
 href = sub["url"];
 if(!href)
  return NULL;
 
 href = canonical_url(url:href, current:current);
 if ( href )
 {
  add_url(url: href, depth: depth+1, referer: current);
  return href;
 }
}


function parse_form(elements, current)
{
 local_var action;
 local_var dyn;

 debug_print(level:2, 'parse_form: elements=', elements, ' current=', current, '\n');

 dyn = follow_dynamic_pages;
 follow_dynamic_pages = FALSE; 
 action = elements["action"];
 # Drupal search box
 if ( action == current && elements['accept-charset'] == 'UTF-8' &&
      elements['method'] == 'post' && elements['id'] == 'search-theme-form' )
 {
   debug_print(level: 2, 'parse_form: drupal search text box\n');
   return NULL;
 }

 if (action == "#" || action == "") action = current;
 action = canonical_url(url:action, current:current);
 follow_dynamic_pages = dyn;
 if ( action )
   return action;
 else 
   return NULL;
}


function ignore_page_CGI(page)
{
  local_var	cgi, idx;

  idx = stridx(page, '?');
  if (idx == 0) return;
  else if (idx > 0) cgi = substr(page, 0, idx - 1);
  else cgi = page;

  not_a_CGI[cgi] = 1;
}

function pre_parse(data, src_page)
{
    local_var php_path, fp_save, data2, url;

  if(Misc[src_page]) return;

    if ("Index of /" >< data)
    {
	    if("?D=A" >!< src_page && "?PageServices" >!< src_page)
	    	{
             	 misc_report = misc_report + string("Directory index found at ", src_page, "\n");
	   	 Misc[src_page] = 1;
		 ignore_page_CGI(page: src_page);
		 set_kb_item( name: 'www/'+port+'/content/directory_index',
		 	      value: src_page );
		 }
    }

    # TBD: add other languages
    if (">[To Parent Directory]<" >< data)
    {
      if (egrep(string: data, icase: 1, pattern: '<br>[ \t*](0?[1-9]|1[0-2])/(0[0-9]|[12][0-9]|3[01])/((199|20[01]|[901])[0-9])[ \t]+([01]?[0-9]|2[0-3]):[0-5][0-9](:[0-5][0-9])?[ \t]+(AM|PM)?.*<A HREF='))
      {
        misc_report += strcat("Directory index found at ", src_page, '\n');
	Misc[src_page] = 1;
	ignore_page_CGI(page: src_page);
	set_kb_item( name: 'www/'+port+'/content/directory_index', value: src_page );
      }
    }
    
    if ("<title>phpinfo()</title>" >< data)
    {
            misc_report = misc_report + string("Extraneous phpinfo() script found at ", src_page, "\n"); 
	    Misc[src_page] = 1;
    }

    ####

    # JBoss JMX Management Console - $HOST ($IP)
    # Administration Console
    if (egrep(string: data, pattern: "<title>[^<]*(Administration|Management) Console", icase: 1))
    {
      url = src_page;
      if ("?" >< url)
        url = ereg_replace(string: url, pattern: "^(/.*)\?.*", replace: "\1");
      set_kb_item(name: "www/"+port+"/console", value: url);
      Consoles[url] = 1;
    }

    ####
    
    if("Fatal" >< data || "Warning" >< data)
    {
    data2 = strstr(data, "Fatal");
    if(!data2)data2 = strstr(data, "Warning");
    
    data2 = strstr(data2, "in <b>");
    if ( data2 ) 
    {
    php_path = ereg_replace(pattern:"in <b>([^<]*)</b>.*", string:data2, replace:"\1");
    if (php_path != data2)
    {
            misc_report = misc_report + string("PHP script discloses physical path at ", src_page, " (", php_path, ")\n");
	    Misc[src_page] = 1;
     }
    }
   }
    
   
    data2 = strstr(data, "unescape");
    
    if(data2 && ereg(pattern:"unescape..(%([0-9]|[A-Z])*){200,}.*", string:data2))
    {
      misc_report += string(src_page, " seems to have been 'encrypted' with HTML Guardian\n");
      guardian ++;
    }
    
    if("CREATED WITH THE APPLET PASSWORD WIZARD WWW.COFFEECUP.COM" >< data)
    {
      misc_report += string(src_page, " seems to contain links 'protected' by CoffeCup\n");
      coffeecup++;
    }

    if("SaveResults" >< data)
    { 
    fp_save = ereg_replace(pattern:'(.*SaveResults.*U-File=)"(.*)".*"', string:data, replace:"\2");
    if (fp_save != data)
     {
            misc_report = misc_report + string("FrontPage form stores results in web root at ", src_page, " (", fp_save, ")\n");
	    Misc[src_page] = 1;
     }
   }
}

function add_ext_URL(u, host, proto, current)
{
  local_var	e;

  if (match(string: u, pattern: "javascript:*", icase: 1)) return;

  if (match(string: u, pattern: "mailto:*@*", icase: 1))
  {
    add_mailto(mailto: u, current: current);
    return;
  }

  if (ext_URL_nb >= 200) return;
  if (! isnull(ext_URL_hash[u])) return;

  if (isnull(proto) || isnull(host))
  {
    e = eregmatch(string:u, pattern:"^([a-z][a-z0-9.+-]*)://([^/:?]+)(:[0-9]+)?([/?].*)?$", icase: TRUE);
    if (isnull(e))
    {
      # Parse URLs like news:news.example.com or 
      # mailto:example@example.com?subject=example
      e = eregmatch(string:u, pattern:"^([a-z][a-z0-9.+-]*):([^/:?]+)(:[0-9]+)?([/?].*)?$", icase: TRUE);
      if (isnull(e))
      {
        debug_print("add_ext_URL: cannot parse URL ", u);
        return;
      }
    }
    proto = e[1];
    host = e[2];
  }
  proto = tolower(proto);
  host = tolower(host);
  if (ext_URL_nb_per_host[host] >= 50) return;

  ext_URL_nb_per_host[host] ++;
  ext_URL_nb ++;
  set_kb_item(name: "www/"+port+"/links/"+ext_URL_nb, value: u);
  ext_URL_hash[u] = 1;
  if (current)
    set_kb_item(name: "www/"+port+"/referers/"+ext_URL_nb, value: current);
}


function parse_main(current, data, depth)
{
 local_var tokens, elements, cgi, form_cgis, form_rcgis, form_action, form_cgis_level, args, store_cgi;
 local_var argz, token, autocomplete1, autocomplete2;
 local_var argz2, url, k;
 local_var	arg_h, pass_l;
 local_var current_select, current_select_name;
 local_var form_to_visit, str, tmp, i, r;
 local_var form_method, form_enctype, a;
 local_var script_level;
 local_var current_script_start, current_script_end;
 local_var positions;
 local_var t, max;

 
 current_select = make_list();
 form_cgis = make_list();
 form_action = make_list();
 form_enctype = make_list();
 form_method = make_list();
 form_cgis_level = 0;
 argz = NULL; arg_h = make_array(); pass_l = make_list();
 autocomplete1 = NULL; autocomplete2 = NULL;
 store_cgi = 0;
 current_script_start = current_script_end = -1;
 tokens = token_split(content: data);
 if ( isnull(tokens) ) return;
 positions = tokens[1];
 tokens = tokens[0];
 max = max_index(tokens);
 script_level = 0;

 # ignore CGIProxy to avoid crawling the entire www via the target being scanned
 if (
   '<title>Start Using CGIProxy</title>' >< data ||  # shows up on nph-proxy.cgi
   '<script type="text/javascript">_proxy_jslib_pass_vars("' >< data # shows up on proxied pages
 )
 {
   return;
 }

 for ( t = 0 ; t < max ; t ++ )
 {
   token = tokens[t];
   elements = token_parse(token:token, position:positions[t]);
   if(!isnull(elements))
   {
    if(elements["onclick"])
    	parse_javascript(elements:elements, current:current, depth:depth);

    if ( elements["nasl_token_type"] == "applet")
        parse_java(elements:elements);
	
    if ( elements["nasl_token_type"] == "script" && !isnull(elements["src"]) )
    {
	if ( script_level == 0 ) current_script_start = elements["nasl_token_position"];
	script_level ++;
	parse_javascript_src(elements:elements, current:current, depth: depth);
    }
    else if ( elements["nasl_token_type"] == "script" )
    {
	if ( script_level == 0 ) current_script_start = elements["nasl_token_position"];
	script_level ++;
    }
    else if ( elements["nasl_token_type"] == "/script" )
    {
	script_level --;
	if ( script_level <= 0 )
 	{
	current_script_end = elements["nasl_token_position"];
	if ( current_script_start > 0 && current_script_end <= strlen(data) ) parse_javascript(elements:elements, current:current, depth: depth, src:substr(data, current_script_start - 1, current_script_end));
	current_script_start = current_script_end = -1;
	script_level = 0; 
	}
    }


    if(elements["nasl_token_type"] == "a" 	  || 
       elements["nasl_token_type"] == "link" 	  ||
       elements["nasl_token_type"] == "frame"	  ||
       elements["nasl_token_type"] == "iframe"	  ||
       elements["nasl_token_type"] == "area")
        if( parse_href_or_src(elements:elements, current:current,depth:depth) == NULL) {
           debug_print(level: 20, "ERROR - ", token, " ", elements, "\n");
	  }
    if (elements["nasl_token_type"] == "embed")
      parse_embed(elements:elements, current:current,depth:depth);

    if(elements["nasl_token_type"] == "img")
    	parse_dir_from_src(elements:elements, current:current);
	
    if(elements["nasl_token_type"] == "meta")
    	parse_refresh(elements:elements, current:current,depth:depth);
			  
    if( elements["nasl_token_type"] == "form" )
    {
      if ( current_script_start >= 0 )
      {
	# Make sure stuff like
	#	windowCode += "<body bgcolor='#2b4e67' style='color:white'> <form name='testForm' method='post' action='"+serviceURL+" enctype='multipart/form-data'>";
	# does not match

	if ( elements["action"] =~ '" *\\+' ) continue;
	if ( elements["action"] =~ '\' *\\+' ) continue;
      }

      form_action[form_cgis_level] = elements["action"];
      form_method[form_cgis_level] = elements["method"];
      form_enctype[form_cgis_level] = elements["enctype"];
      form_rcgis[form_cgis_level] = elements["action"];
      cgi = parse_form(elements:elements, current:current);
      if( cgi )
      {
       
       form_cgis[form_cgis_level] = cgi;
       store_cgi = 1;
      }
      form_cgis_level ++;
      autocomplete1 = elements["autocomplete"];
    }
    
   if( elements["nasl_token_type"] == "/form")
    {
     form_cgis_level --;
     if ( form_cgis_level < 0 ) form_cgis_level = 0; # Bug on the page
     if (strlen(argz2) > 0 )
     {
      check_for_cleartext_password(cgi:form_rcgis[form_cgis_level], args:argz2, where:current);
      check_for_autocomplete_password(cgi:form_rcgis[form_cgis_level], args:argz2, where:current, autocomplete_form: autocomplete1, autocomplete_field: autocomplete2);
     }
     if (store_cgi && ! isnull(cgi))
     {
      a = canonical_url(url: form_action[form_cgis_level], current: current);
      add_cgi(cgi:form_cgis[form_cgis_level], args:argz, form: a, method: form_method[form_cgis_level], referer: current, enctype: form_enctype[form_cgis_level]);
      add_cgi_args_from_hash(cgi:form_cgis[form_cgis_level], args: arg_h, form: a, method: form_method[form_cgis_level], enctype: form_enctype[form_cgis_level], passw: pass_l);
     }

     # TBD: use the hash representations of the CGI, not the string
     if ( follow_dynamic_pages && ! isnull(form_cgis[form_cgis_level]))
     {
     debug_print(level: 5, "** before add_url: argz=", argz);
      #tmp = split(argz, sep:' ', keep:0);
      tmp = argz;
      url = form_cgis[form_cgis_level] + "?";
      i = 0;
      while (strlen(tmp) > 0)
      {
        r = eregmatch(string: tmp, pattern: "^([^ ]*) \[([^]]*)\] (.*)$");
        if (isnull(r))
        {
          r = eregmatch(string: tmp, pattern: "^([^\[\]]*) \[([^]]*)\] (.*)$");
          if (isnull(r))
          {
            debug_print("parse_main(", get_host_name(), ":", port, "): cannot parse: ", tmp);
            break;
          }
	}
	if (i) url = strcat(url, "&");
	url = strcat(url, r[1], "=", r[2]);
	tmp = r[3];
	i ++;
      }
      add_url(url:url, depth: depth+1, referer: current);
     }
     argz = "";
     argz2 = "";
     arg_h = make_array(); pass_l = make_list();
     autocomplete2 = NULL;
     store_cgi = 0;
    } 
   
   if( elements["nasl_token_type"] == "input" ||
       elements["nasl_token_type"] == "textarea" )
    {
      if(elements["name"])
      {
    	 argz += string( elements["name"], " [", elements["value"], "] ");
	 k = strcat(elements["name"]);
	 if (isnull(arg_h[k])) arg_h[k] = elements["value"];
      }
      if ( elements["type"] == "password" && !isnull(elements["name"]) )
 	{
	 if ( isnull(pass_l) ) 
	   pass_l = make_list(elements["name"]);
	 else
	   pass_l = make_list(pass_l, elements["name"]);
    	 argz2 += string( "Input name : ", elements["name"], "\n");
	 if ( elements["value"] )
	   argz2 += string("Default value :  ", elements["value"], "\n");
         if (elements["autocomplete"]) autocomplete2 = elements["autocomplete"];
	}
    }
   if ( elements["nasl_token_type"] == "select" )
    {
	current_select_name = elements["name"];
    }
   if ( elements["nasl_token_type"] == "/select" )
	{
	 i = rand() % max_index(current_select);
	 argz += string(current_select_name, " [", current_select[i], "] ");
	 # Remember all the values
	 k = strcat(current_select_name);
	 if (isnull(arg_h[k]))
	   arg_h[k] = current_select;
	 else
	   arg_h[k] = make_list(arg_h[k], current_select);
	 current_select = make_list();
	}
   if ( elements["nasl_token_type"] == "option" )
	{
	 current_select[max_index(current_select)] = elements["value"];
	}
   }
 }
}

function check_for_cleartext_password(cgi, args, where)
{
 local_var report;
 if ( cgi =~ "^https://" ) return;
 else if ( cgi !~ "^http://" && SSL_Used != 0 ) return;

 
 report += 'Page : ' + where + '\n';
 report += 'Destination page : ' + cgi + '\n';
 report +=  args;

 ClearTextPasswordForms += report + '\n\n';
}

function check_for_autocomplete_password(cgi, args, where, autocomplete_form, autocomplete_field)
{
 local_var report;

 autocomplete_field = tolower(autocomplete_field);
 autocomplete_form = tolower(autocomplete_form);
 if ("off" >< autocomplete_field) return;
 if ("on" >!< autocomplete_field && "off" >< autocomplete_form) return;
 report = strcat('Page : ', where, '\nDestination Page : ', cgi, '\n', args, '\n\n');
 AutoCompletePasswordForms = strcat(AutoCompletePasswordForms, report, '\n\n');
}

#----------------------------------------------------------------------#
#				MAIN()				       #
#----------------------------------------------------------------------#


start_page = script_get_preference("Start page : ");
if(isnull(start_page) || start_page == "")start_page = "/";

max_pages = int(script_get_preference( "Number of pages to mirror : " ));
if(max_pages <= 0)
  if (COMMAND_LINE)
   max_pages = 9999;
  else
   max_pages = 1000;

follow_dynamic_pages = script_get_preference("Follow dynamic pages : ");
if ( follow_dynamic_pages && follow_dynamic_pages == "yes" )
    follow_dynamic_pages = TRUE; 
else
    follow_dynamic_pages = FALSE; 

num_cgi_dirs = 0;
if ( thorough_tests ) 
	max_cgi_dirs = 1024;
else 
	max_cgi_dirs = 16;

excluded_RE = script_get_preference("Excluded items regex :");
if (!isnull(excluded_RE) && strlen(excluded_RE) == 0) excluded_RE = NULL;
if (! isnull(excluded_RE))
 set_kb_item(name: "Settings/HTTP/excluded_items_regex", value: excluded_RE);

max_depth = int(script_get_preference("Maximum depth : "));
if (max_depth <= 0) max_depth = 16777216;

embedded = get_kb_item("Settings/HTTP/test_embedded");
if (! embedded ) embedded = get_kb_item("Settings/PCI_DSS");
port = get_http_port(default: 80, embedded: embedded, dont_break: 1);

if (get_kb_item("Settings/disable_cgi_scanning") &&
    get_kb_item("www/"+port+"/no_web_app_tests"))
  exit(0, "Web application tests are disabled on port "+port+".");

if ( get_kb_item("Settings/HTTP/automatic_http_login") ||
     get_kb_item("/tmp/www/"+port+"/automatic_http_login"))
{
  automatic_http_login = 1;
  # In some rare cases (demo web app), login & password are already filled in
  http_login = get_kb_item("http/login");
  http_pass = get_kb_item("http/password");
  if (! http_login || ! http_pass) automatic_http_login = 0;
  # Consistency check: are we already logged in?
  lt = int(get_kb_item("www/"+port+"/login_time"));
  if (lt > 0) automatic_http_login = 0;  
}

ext_URL_nb = 0; ext_URL_nb_per_host = make_array();


if (COMMAND_LINE)	# TESTS
{
 max_pages = 1000; debug_level = 1; follow_dynamic_pages = TRUE;
 MAX_token_nb = 64*16; MAX_arg_nb = 512 * 16; MAX_argval_nb = 2048;
 # start_page = '/';
 # excluded_RE = "/phpmyadmin/|/server_privileges\.php|logout|security\.php|/mutillidae/|/setup.php|/vulnerabilities/csrf/";
 # debug_level = 4;
}

if ( get_port_transport(port) != ENCAPS_IP )
	SSL_Used = 1;
else
	SSL_Used = 0;

URLs = split(start_page, sep: ":", keep: 0);
foreach p (URLs) URLs_hash[p] = 0;
# Imported logs from web_app_test_settings.nasl
l = get_kb_list("WebAppTests/ImportedURL");
if (! isnull(l))
{
  n = max_index(URLs);
  foreach p (make_list(l))
  {
    URLs_hash[p] = 0;
    URLs[n++] = p;
  }
}

dirs = get_kb_list(string("www/", port, "/content/directories"));
if(dirs) URLs = make_list(URLs, dirs);

dirs = get_kb_list(string("www/", port, "/content/directories/require_auth"));
if(dirs) URLs = make_list(URLs, dirs);

MAILTOs_hash = make_array();


ID_WebServer = 0;
Apache = 0;
iPlanet = 0;

CGIs = make_list();
Dirs = make_list();
Misc = make_array();
not_a_CGI = make_array();
Consoles = make_array();

CGI_Dirs_List = make_array();

URLs_30x_hash = make_array();
URLs_auth_hash = make_array();
URLs_special_headers_hash = make_array();


Code404 = make_list();

misc_report = "";
cnt = 0;

RootPasswordProtected = 0;

guardian  = 0;
coffeecup = 0;

start_time = gettimeofday(); req_count = 0;

pass = 0;
while (max_index(URLs) > 0)
{
  pass ++;
  debug_print(level: 1, '**** pass=', pass, ' - port=', port);
  http_reauthenticate_if_needed(port: port);
  url_l = URLs;
  url_ref_l = URL_ref;
  URLs = make_list(); URL_ref = make_list();
  foreach u (url_l)
  {
    u = remove_dots(url: u);
    u = sanitize_url(u: u);
    if( ! URLs_hash[u] && 
        (isnull(excluded_RE) || 
        ! ereg(string: u, pattern: excluded_RE, icase: 1)) )
    {
      dpt = URL_depth[u];
      if (isnull(dpt)) dpt = pass - 1;
      debug_print(level: 2, 'URL=', u, ' - depth=', URL_depth[u], ' - pass=', pass, '\n');
      page = retr(port:port, page: u, depth: dpt, referer: url_ref_l[u]);
      if (!isnull(page))
	{
	  cnt ++;
	  pre_parse(src_page: u, data:page);
	  parse_main(data:page, current: u, depth: dpt);
 	  URLs_hash[u] = 1;
	  if(cnt >= max_pages) break;
	}
    }
  }
  if(cnt >= max_pages) break;
}


if(cnt == 1)
{
 if(RootPasswordProtected)
 {
  set_kb_item(name:string("www/", port, "/password_protected"), value:TRUE);
 }
}

#

report = "";


foreach foo (keys(CGIs))
{
 args = CGIs[foo];
 if (
   isnt_a_CGI(cgi: foo, args: args) ||
   ereg(string: foo, pattern: excluded_RE, icase: 1)
 )
 {
   forget_CGI(cgi: foo);
   continue;
 }
 if(!args) args = "";
 set_kb_item(name:string("www/", port, "/cgis"), value:string(foo, " - ", args));
 if ( strlen(args) > 72 ) args = substr(args, 0, 69) + "...";
  
 if(!report) 
 	report = string("The following CGI have been discovered :\n\nSyntax : cginame (arguments [default value])\n\n", foo, " (", args, ")\n");
 else
 	report = string(report, foo, " (", args, ")\n");

 if ( strlen(report) > 40000 ) break;
}

if(misc_report)
{ 

 report =  string(report, "\n\n", misc_report);
}

remember_mailto();

if(guardian)
{
 report += string("
 
HTML Guardian is a tool which claims to encrypt web pages, whereas it simply
does a transposition of the content of the page. It is not a safe
way to make sure your HTML pages are protected.

See also : http://www.securityfocus.com/archive/1/315950
BID : 7169");
}


if(coffeecup)
{
 report += "
 
CoffeeCup Wizard is a tool which claims to encrypt links to web pages,
to force users to authenticate before they access the links. However,
the 'encryption' used is a simple transposition method which can be 
decoded without the need of knowing a real username and password.

BID : 6995 7023";
}

if (http_login_form && http_login_fields)
  report = strcat(report, '\n\nNessus attempted HTTP login on this form using its default values :\n',
'\nMethod : ', http_login_meth,
'\nURL    : ', http_login_form,
'\nData   : ', http_login_fields, '\n'); 


if (MAX_arg_nb < 0)
  set_kb_item(name: 'www/'+port+'/error/too_many_arg', value: TRUE);
if (MAX_argval_nb < 0)
  set_kb_item(name: 'www/'+port+'/error/too_many_arg_val', value: TRUE);
if (MAX_token_nb < 0)
  set_kb_item(name: 'www/'+port+'/error/too_many_token', value: TRUE);

end_time = gettimeofday();
dt = difftime(t1: start_time, t2: end_time);
dt /= 1000;

if (req_count > 0 && dt > 0)
{
  req_per_sec = req_count * 1000 / dt;
  ms_per_req = dt / req_count;
  set_kb_item(name: 'www/'+port+'/requests_per_sec', value: req_per_sec);
  set_kb_item(name: 'www/'+port+'/ms_per_request', value: ms_per_req);
  if (COMMAND_LINE || report_verbosity > 1)
  {
    t = dt % 1000;
    if (t < 10)
      t = strcat('00', t);
    else if (t < 100)
      t = strcat('0', t);
   t = strcat(dt / 1000, '.', t);
    report = strcat(report, '\n', req_count, ' requests were sent in ', t, ' s = ', req_per_sec, ' req/s = ', ms_per_req, ' ms/req\n');
  }
}

if(strlen(report))
{
 security_note(port:port, extra:'\n'+report);
}

if ( strlen(ClearTextPasswordForms) )
{
 set_kb_item(name:"www/" + port + "/ClearTextPasswordForms", value:ClearTextPasswordForms);
}

if ( strlen(AutoCompletePasswordForms) )
{
 set_kb_item(name:"www/" + port + "/AutoCompletePasswordForms", value:AutoCompletePasswordForms);
}

cj = strcat("webmirror-", port);
store_cookiejar(cj);
