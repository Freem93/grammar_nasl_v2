#TRUSTED 7cd2f5ea36b642db52b513d670a6bf001bf6713676ef58a29c33507affe990f9b7e32b817138ba0dde23f91ac74961a6ad67fd27467d602a3204d938f58881b7a5852d6c34bd3ce2011817b6d892ee852a8a372a253e6961db5873af84d22b2515e6c6b63b00f92c028a926d91c8c7b7a598fc9fbaa4cd4880ace63731154f2e1b264a696f2f04811dc8e4dbf8c557fd8fd6c0dfc51e67f379875d024092f64f992e6928869fb61b90fa8dc09e654dfc0a4322d04d3323d3ba844f218195004e2daafe5112b1c58b81632c19366a71526a7548aff762566da74abf7daf170a67f01474246926a845009bac19b77854229dfecdc494a5988ff1aac995062525f8f88f99513db961d71e1734e0a6c8e39cb47756c00ce90e8997cc4ab4bcd59cefa1fdbbcbc0a223c09219f17b61646a9e7e8f860ec3eeae8f7ce202d32e2baa6e2ae027da95db81fe989d3461be40d0e8af055a83c027264a17ce66b7222825c939c97d57bf219feef3b1e75eceb838d2e36b89a6d3e2f87696d8a02c16a3049ddcb1b53f30bf954000ca0350eebe4fd662f11027a3bf74f9616310adf69f330842f4b7fc403d9ed7279ac198829620850191bf02c211cbc515fca105bc41e5179e5c0151604fed183217aa4322c3fe66521480145ff18d27bf5681abea6b806dfbdff7e278453352d0406aaecda8e7e2218f0f9719fb3576a8ebd5a9ef889faf
# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# http_login.inc
# Revision: 1.8

global_var	CookieJar_is_disabled;
global_var	HttpLogin_reauthentication_OK, HttpLogin_reauthentication_KO;

function http_check_authentication(port, check_page, regex, re_invert, re_headers, re_icase, follow_redirect)
{
  local_var	r, s, flag;

  if (strlen(check_page) == 0 || strlen(regex) == 0) return "";

  r = http_send_recv3(method:"GET", item: check_page, port: port, follow_redirect: follow_redirect);
  if (isnull(r))
  {
    return strcat("request failed: GET ", check_page);
  }
  if (re_headers)
    s = egrep(string: r[0]+r[1], pattern: regex, icase: re_icase);
  else
    s = egrep(string: r[2], pattern: regex, icase: re_icase);
  flag = (strlen(s) > 0);
  if (flag)
    debug_print(level: 3, 'http_check_authentication extracted pattern: ', chomp(s));
  if (re_invert) flag = ! flag;
  if (! flag)
  {
    if (report_verbosity > 1)
      return strcat("post-authentication test failed", '.\nThe web server answered :\n\n', r[0], r[1], '\n', r[2]);
    else
      return strcat("post-authentication test failed");
  }
  return "OK";
}

# This function returns an empty string for "maybe", "OK" if authentication 
# succeeded (the control page could be check). Any other string is an error 
# message.
function http_form_login(port, page, form, fields, follow_redirect, 
	 		 save_cookies, check_page, regex, re_invert,
			 re_headers, re_icase, method)
{
  local_var	r, trp, h, e;

  h = make_array();
  e = "";

  if (page)
  {
    r = http_send_recv3(port: port, item: page, method: 'GET', follow_redirect: follow_redirect);
    if (isnull(r))
    {
      debug_print("Broken connection on port ", port, " after GET ", page);
      return strcat("request failed: GET ", page);
    }

    trp = get_port_transport(port);
    h["Referer"] = build_url(port: port, qs: page);
  }

  if (! method) method = "POST";

  if (method == "POST")
  {
  h["Content-Type"] = "application/x-www-form-urlencoded";
  r = http_send_recv3( port: port, method: 'POST', 
      		       follow_redirect: follow_redirect,
      		       add_headers: h, 
    		       item: form, data: fields);
  }
  else
  {
    r = http_send_recv3( port: port, method: 'GET', 
      		       follow_redirect: follow_redirect,
    		       item: form + "?" + fields);
  }
  if (isnull(r))
  {
    debug_print("Broken connection on port ", port, " after ", method, " ", form);
    return strcat("request failed: ", method, " ", form);
  }

  # Failed - permission denied or bad gateway or whatever
  # This happens sometimes when we follow redirections, but we might be 
  # authenticated anyway.
  if (r[0] =~ "^HTTP/[01.]+ +[45][0-9][0-9] ")
  {
    debug_print("Permission denied: code=", r[0]);
    e =  "Permission denied or other HTTP error on "+method+" request";
  }
  # All other codes are considered as OK. We might get a 30x code too!

  r = http_check_authentication(port: port, check_page: check_page, regex: regex, re_invert: re_invert, re_headers: re_headers, re_icase: re_icase, follow_redirect: follow_redirect);

  if (r == "")
  {
    # We could not check if we are authenticated but we got an error first. 
    # Let's return it.
    if (e != "") return e;
  } else if (r != "OK")	# Error
    return r;

  # Here, we are sure that we are authenticated (OK) 
  # or nothing proves that we are not.
  if (! CookieJar_is_disabled && save_cookies) store_cookiejar("FormAuth");
  return r;
}


function http_login_take_lock(port, now, delay)
{
  local_var	k, t, v;

  if (nasl_level() < 3000) return 1;	# Cannot work

  k = "/tmp/http_login/"+port+"/lock";
  t = get_kb_item(k);
  if (t)
  {
    v = split(t, sep:'-', keep: 0);
    t = now - int(v[0]);
    if (t > delay || t < 0)
    {
      debug_print("http_login_take_lock: old lock (", t, " s ago) deleted (port=", port, ")");
      rm_kb_item(name:k);
    }
    else
    {
      debug_print(level: 2, "http_login_take_lock: lock taken ", t, " s ago");
      return 0;
    }
  }
  v = strcat(now, '-', rand());
  replace_kb_item(name:k, value: v);

  if (get_kb_item(k) != v)
  {
    debug_print("http_login_take_lock: lock stolen");
    return 0;
  }
  return 1;
}

function http_login_release_lock()
{
  local_var	k, port;
  if (nasl_level() < 3000) return 1;	# Cannot work
  port = _FCT_ANON_ARGS[0];
  k = "/tmp/http_login/"+port+"/lock";
  rm_kb_item(name: k); 
  return 1;
}


# This function should only be called if a lock has been taken
function http_login_incr_count(port, kb)
{
  local_var	k, n;

  k = "www/"+port+"/"+kb;
    n = get_kb_item(k);
    n ++;
    replace_kb_item(name: k, value: n);
  }

function http_reauthenticate_if_needed(port, save_cookies)
{
  local_var	page, form, fields, time, e, delay, now;
  local_var	cp, re, iv, hd, ic, fr, i, mt;

  cp = get_kb_item("www/"+port+"/check_page");
  re = get_kb_item("www/"+port+"/check_regex");
  iv = get_kb_item("www/"+port+"/regex_invert");
  hd = get_kb_item("www/"+port+"/regex_headers");
  ic = get_kb_item("www/"+port+"/regex_icase");
  fr = get_kb_item("www/"+port+"/login_follow_30x");

  e = http_check_authentication(port: port, check_page: cp, regex: re, re_invert: iv, re_headers: hd, re_icase: ic, follow_redirect: fr);
  if (e == "OK") return;

  # Ideally, we should take a mutex here, but the functions are privileged
  # and we do not want to sign all web scripts.

  if (e != "")		# use a tiny delay if we are disconnected
    delay = get_read_timeout();
  else
    delay = get_kb_item("www/"+port+"/login_delay");
  if (delay <= 0) return;

    time = get_kb_item("www/"+port+"/login_time");
  now = unixtime();
  if (time + delay > now)
    {
    debug_print(level: 2, 'Will not try to re-authenticate on port ', port, ' before ', time + delay - now, ' seconds\n');
      return;
    }

  if (! http_login_take_lock(port: port, now: now, delay: delay))
  {
    # Try to reload the cookie jar, in case another plugin updated it
    if (e != "") sleep(get_read_timeout());
    load_cookiejar(jar:"FormAuth");
    return;
  }

  page = get_kb_item("www/"+port+"/login_page");
  form = get_kb_item("www/"+port+"/login_form");
  fields = get_kb_item("www/"+port+"/login_fields");
  mt = get_kb_item("www/"+port+"/login_meth");

  e = http_form_login(port: port, page: page, form: form, fields: fields,
    save_cookies: save_cookies, method: mt, 
        check_page: cp, regex: re, re_invert: iv, re_headers: hd, re_icase: ic);
  if (e == "OK")
  {
    replace_kb_item( name: "www/"+port+"/"+SCRIPT_NAME+"/auth_OK", 
    		     value: ++ HttpLogin_reauthentication_OK);
    debug_print("Successful authentication on port ", port);
  }
  else if (e != "")
  {
    replace_kb_item( name: "www/"+port+"/"+SCRIPT_NAME+"/auth_KO", 
    		     value: ++ HttpLogin_reauthentication_KO);
    debug_print("Web authentication failed on port ", port, ": ", e);
  }
  replace_kb_item(name: "www/"+port+"/login_time", value: unixtime());

  http_login_release_lock(port);
}

