#TRUSTED 9780236b2235c729526c462366f213a52f05c7a8402a0602d6f1ff2bb184c6d8357fb130a469c47cffbc0661ba57aa2003089b34669d5749e7aa4ecc54c8d56b62fb206640914ae1cc10b96457cd4dc9b51afd423a96d7021f83999b08d65f4bb2c6da54125b04a0b4512004d2f7c23b906ea311563aa3fc5a32d514d09070b9e6634359590f1856a3897c326a5a21febdb48657146239b9c1ebeca71fbdece544b09fb233647cc439f44c2edd3921479bdf93ae2a319ea48e7a2cea11d617f6b15be0ee4e75d207b45fe0ae2762749652faaa81077f148b3f63bc0f544915deb5c94982142558f0128e3fcc1b5039b6cbf526d2cf2882ccd642f9cf6303c0c8c2f689fbc35d22403d911475c5436c8739f79ee84f327615383e484d0de84f6d6291cdb0f245f597caa4848ac78777c2c26b713aa4ca65a80ff99c553426002239275fbd626455725f8eca7bc95e16903258d10a50859c763a6dd40a782a87564cd83cc3aeaf2cb1f2e78fe553295cd928e2dc0b1758810daaba1b011216254873240ba258a28d5355a74cd7638a03a6904f0017ba853f36759eacaafe87368e7ba670e12234bacb71e170eae8d5a9926a2f129e68ce3f95ca07ecdb3ad0d1bf35a21b7dcdc858e955e5b69dec32170f30838d478b41407688b3e7229ba1b62b7ffa86788e10604c2b02eefe37dff5507ac9a59aba4c3ed63dc1b5ef17bb69a6
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(42893);
 script_version("1.8");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/02/17");

 script_name(english:"HTTP cookies import");
 script_summary(english:"Import HTTP cookies in Netscape format");

 script_set_attribute(attribute:"synopsis", value: "HTTP cookies import.");
 script_set_attribute(attribute:"description", value:
"This plugin imports cookies for all web tests.

The cookie file must be in 'Netscape format'.

It does not perform any test by itself.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/25");

 script_set_attribute(attribute:"plugin_type", value:"settings");
 script_end_attributes();

 script_category(ACT_SETTINGS);
 script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
 script_family(english:"Settings");

 script_add_preference(name: "Cookies file : ", type: "file", value:"");
 script_dependencie("ping_host.nasl", "global_settings.nasl");
 exit(0);
}

global_var	debug_level;

include("misc_func.inc");

global_var	same_hosts_l;
same_hosts_l = make_array();

function _wm_same_host(h)
{
 local_var	n, i;
 n = tolower(get_host_name());
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

#### Functions from global_settings.inc

# a0 to a9 parameters are useless. They were added to suppress a warning
# with old NASL2 interpreters
function debug_print(level, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9)
{
 local_var	msg, i, l;

 if (isnull(level)) level = 1;
 if (debug_level < level) return;
 msg = strcat(SCRIPT_NAME, '(', get_host_ip(), '): ');
 foreach i (_FCT_ANON_ARGS) { msg = string(msg, i); }
 l = strlen(msg);
 if (l == 0) return;
 if (msg[l-1] != '\n') msg += '\n';
 display("DEBUG: ", msg);
}

function err_print(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9)
{
 local_var	msg, i, l;

 if ( NASL_LEVEL < 2191 ) return;
 msg = strcat(SCRIPT_NAME, '(', get_host_ip(), '): ');
 foreach i (_FCT_ANON_ARGS) { msg = string(msg, i); }
 l = strlen(msg);
 if (l == 0) return;
 if (msg[l-1] != '\n') msg += '\n';
 display("ERR: ", msg);
}

#### Functions from http_cookie_jar.inc, to avoid signing it

global_var	CookieJar_value, CookieJar_version, CookieJar_expires,
		CookieJar_comment, CookieJar_secure, CookieJar_httponly,
		CookieJar_domain, CookieJar_port,
		CookieJar_is_disabled, CookieJar_autosave;

function set_http_cookie(key, name, path, value, domain, secure, version)
{
  if (isnull(key))
  {
    if (isnull(name))
    {
      err_print("set_http_cookie: either key or name must be set!\n");
      return NULL;
    }
    if (! path) path = "/";
    key = strcat(name, '=', path);
  }
  else
  {
    if (! isnull(name))
      err_print("set_http_cookie: key (", key, ") and name (", name, ") cannot be both set! Ignoring name.\n");
  }
  CookieJar_value[key] = value;
  if (isnull(version)) version = 1;
  CookieJar_version[key] = version;
  CookieJar_domain[key] = domain;
  # CookieJar_expires[key] = NULL;
  # CookieJar_comment[key] = NULL;
  if (strlen(CookieJar_autosave) > 0)
    store_1_cookie(key: key, jar: CookieJar_autosave);
}

function store_1_cookie(key, jar)
{
  local_var	val, kbkey;

  kbkey = hexstr(key);
  if (isnull(jar)) jar = "Generic";
  val = CookieJar_value[key];
  if (! isnull(val))
    replace_kb_item(name: "Cookies/"+jar+"/value/"+kbkey, value: val);
  else if (defined_func("rm_kb_item"))
    rm_kb_item(name: "Cookies/"+jar+"/value/"+kbkey);

  val = CookieJar_version[key];
  if (! isnull(val))
    replace_kb_item(name: "Cookies/"+jar+"/version/"+kbkey, value: val);
  else if (defined_func("rm_kb_item"))
    rm_kb_item(name: "Cookies/"+jar+"/version/"+kbkey);

  val = CookieJar_expires[key];
  if (! isnull(val))
    replace_kb_item(name: "Cookies/"+jar+"/expires/"+kbkey, value: val);
  else if (defined_func("rm_kb_item"))
    rm_kb_item(name: "Cookies/"+jar+"/expires/"+kbkey);

  val = CookieJar_comment[key];
  if (! isnull(val))
    replace_kb_item(name: "Cookies/"+jar+"/comment/"+kbkey, value: val);
  else if (defined_func("rm_kb_item"))
    rm_kb_item(name: "Cookies/"+jar+"/comment/"+kbkey);

  val = CookieJar_secure[key];
  if (! isnull(val))
    replace_kb_item(name: "Cookies/"+jar+"/secure/"+kbkey, value: val);
  else if (defined_func("rm_kb_item"))
    rm_kb_item(name: "Cookies/"+jar+"/secure/"+kbkey);

  val = CookieJar_httponly[key];
  if (! isnull(val))
    replace_kb_item(name: "Cookies/"+jar+"/httponly/"+kbkey, value: val);
  else if (defined_func("rm_kb_item"))
    rm_kb_item(name: "Cookies/"+jar+"/httponly/"+kbkey);

  val = CookieJar_domain[key];
  if (! isnull(val))
    replace_kb_item(name: "Cookies/"+jar+"/domain/"+kbkey, value: val);
  else if (defined_func("rm_kb_item"))
    rm_kb_item(name: "Cookies/"+jar+"/domain/"+kbkey);
}

function store_cookiejar()
{
  local_var	k;
  if (isnull(CookieJar_value)) return;
  foreach k (keys(CookieJar_value))
     store_1_cookie(key: k, jar: _FCT_ANON_ARGS[0]);
}

#### end of cookie functions

opt = get_kb_item("global_settings/debug_level");
debug_level = int(opt);
if (debug_level < 0) debug_level = 0;

# Import Netscape cookies

if (script_get_preference("Cookies file : ")) # Avoid dirty warning
  content = script_get_preference_file_content("Cookies file : ");
else
  exit(0, "No cookie file.");

n = 0;
if (strlen(content) > 0)
{
  CookieJar_autosave = NULL;

  lines = split(content, keep: 0);
  content = NULL;	# Free memory
  now = unixtime();

  foreach l (lines)
  {
    if (l =~ '^[ \t]*#') continue; # ignore comments
    if (l =~ '^[ \t]*$') continue; # ignore all whitespace lines
# Fields:
# 0 domain
# 1 flag - indicates if all machines within a given domain can access the variable.
# 2 path
# 3 secure
# 4 expiration - UNIX time
# 5 name
# 6 value
    v = split(l, sep: '\t', keep: 0);
    m = max_index(v);

    if (m < 6 || m > 8)
      exit(1, 'Invalid cookies file (unexpected line).');

    if (v[3] == "TRUE") sec = 1; else sec = 0;
    t = int(v[4]);	# Expiration date

    # nb: Firebug has 8 fields per line, with a field for max-age between 
    #     expiration and cookie name.
    if (m == 8)
    {
      name = v[6];
      val =  v[7];
    }
    else
    {
      name = v[5];
      val =  v[6];
    }

    # Import session cookies, but reject expired cookies
    if (t == 0 || now < t)
    {
      set_http_cookie(path: v[2], domain: v[0], secure: sec, name:name, value:val);
      n ++;
    }
    else
      debug_print(level: 3, "Expired cookie: t=", t, " Path=", v[2], " Domain=", v[0], " Secure=", sec, " Name=", name, " Value=", val);
  }

  if (n == 0)
    exit(1, 'No cookies were found in the given file.');

  debug_print(n, ' cookies imported.\n');
  # It is not always related to authentication, but this will be the main use
  store_cookiejar("FormAuth");
  store_cookiejar();
  lines = NULL;	# Free memory
}
else
  exit(0, "Cookie file is empty.");

