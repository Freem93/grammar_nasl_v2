#TRUSTED 476c6e75690e90be9405f6415d66fef4a660d8820148368e7d1705c659b49167f87916d9b9cf3edd392688f3a79d9c7fad6b7ece4c240199b9a922b5f0882d150666fa1ae3ce4511acd86b366048f02a2230c1bbad4ebbb813b7b4101089b272958e4de64ac3d8760ab0a352a9dda7a9796189b37a79155cf6084289afd38b83c2e580f5e4fc368da67a0d2c71d31e5f9eff71422292e3584c25c7dd841d77f0af4371554355062517bf879ffe0364f8a400ad17420aa7b52483ad4fcea7ed70b24feb10aa094d1fc01b9a032e3dea012c4785c7e4b005db6d4543e871b2729cbbd4cf1e7335b64012b5cb534847d412884dc9289c79c0d08afea24a292db8516a705b63d4e4d03aa32d120643b23f51b38fb5a7563735933d4ca8892e73739df6035485f06cd4e20634e50afb918d27a1e90bba45b69c0284d9648831535677efc4448f10059316ce3930319238977f2e69f9c37c99a8c6e8ed6f574689530eb8128c6fb7221ad2ca3ee26e5bb985f14661a7d39d325a1a87b7f4a95f9614e93e17cb4fae849af3a1dcc3c598fccd032f29c73863115841c10d30ecbdd2a86932852e4917f44abb59f642f55ca13d09493a6f4af01458514674185a7d7271b26d94306b428e04dc22de5945b3548f1f7df0c14452a7f01251bc9285c31429b3bbf149e8502d4f77cc3c942f55833bd3941ae6a5584ebfd79bd6a46f6edec3c8
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
# http.inc
# Revision: 1.27

# You need to include global_settings.inc and misc_func.inc
include("byte_func.inc");
include("gunzip.inc");
include("http_cookie_jar.inc");
include("http_request.inc");
include("http_misc_func.inc");
include("http_network.inc");
include("http_login.inc");


function wont_test_cgi(port, embedded)
{
 local_var	no404;
 if (get_kb_item("Settings/disable_cgi_scanning"))  return 1;
 if (! get_port_state(port)) return 1;
 if (get_kb_item("Services/www/" + port + "/broken")) return 1;

 if (! embedded && get_kb_item("Services/www/" + port + "/embedded"))
   return 1;
 no404 = get_kb_item(strcat("www/no404/", port));
 if (strlen(no404) >= 1) return 1;
 return 0;
}

function parse_http_headers(status_line, headers, sep)
{
  local_var	v, line, s, k, err;

  if (isnull(headers)) return NULL;

  v = make_array();
  err = 0;
  foreach line (split(headers, keep: 0))
  if (strlen(line) > 0)
  {
    s = eregmatch(string: line, pattern: '^([A-Z_][A-Z0-9_-]*)[ \t]*:[ \t]*(.*)$', icase: 1);
    if (isnull(s))
    {
      debug_print('parse_http_headers: cannot parse HTTP header -> ', line);
      err ++;
      continue;
    }
    k = tolower(s[1]);
    if (isnull(v[k]))
      v[k] = s[2];
    else
    {
      if (isnull(sep))
      {
        debug_print('parse_http_headers: repeated HTTP header ', s[0], '\n');
	sep = ',';
      }
      v[k] = strcat(v[k], sep, s[2]);
    }
    # No use to call chomp(), split(keep: 0) already removed \r\n
  }
  if (status_line)
  {
    v['$status'] = chomp(status_line);
    k = eregmatch(string: status_line, pattern: '^HTTP/[01]\\.[01]+ +([0-9]+) ');
    if (! isnull(k))
      v['$code'] = int(k[1]);
    else
    {
      debug_print('parse_http_headers: cannot parse status line -> ', status_line);
      err ++;
  }
  }
  if (err > 0) v['$errors'] = err;
  return v;
}

# Do not use this function for generic XSS (due to the web server for example)
# as it interprets the HTTP return code strictly
function test_cgi_xss(port, cgi, qs, pass_re, pass2_re, pass_str, ctrl_re, dirs, add_headers, low_risk, high_risk, sql_injection, silent, force, embedded, follow_redirect, no_qm)
{
  local_var	item, no404, dir, prevdir, r, xt, robust_n, u;
  local_var	res, z;

  if (! force && get_kb_item(string("www/", port, "/generic_xss")))
    return 0;

  if (report_paranoia < 2)
  {
    if (isnull(ctrl_re) && isnull(pass2_re) && 
        (isnull(pass_re) || isnull(pass_str)) )
     return 0;
  }
  no404 = get_kb_item('www/no404/'+port);
  if (! embedded)
  {
    if (cgi =~ ".php" && ! can_host_php(port: port)) return 0;
    if (cgi =~ ".asp" && ! can_host_asp(port: port)) return 0;
  }
  if (isnull(dirs)) dirs = make_list(cgi_dirs(), "");
  prevdir = NULL;
  foreach dir (sort(dirs))
  {
    if (!isnull(prevdir) && dir == prevdir) continue;
    prevdir = dir;
    item = strcat(dir, cgi);
    if (item =~ "^[^/]") item = strcat("/", item);
    if (get_kb_item("/tmp/XSS/"+port+item)) return 0; # No need to report several XSS
    if (get_kb_item("/tmp/404/"+port+item)) continue;

    # Suppress the question mark if requested.
    u = item;
    if (!no_qm)
      u += "?";
    u += qs;

    r = http_send_recv3(method: "GET", item: u, port: port, add_headers: add_headers, follow_redirect: follow_redirect);
    if (isnull(r)) return 0;
    if ( r[0] =~ "^HTTP/1\.[01] +404 " ||
        (no404 && no404 >< r[2]) )
    {
      set_kb_item(name: "/tmp/404/"+port+item, value: TRUE);
      continue;
    }
    if (r[0] =~ "^HTTP/1\.[01] +200 ")
    {
      if ((isnull(pass_str) || pass_str >< r[2]) &&
      	  (isnull(pass_re)  || egrep(string: r[2], pattern: pass_re)) &&
	  (isnull(pass2_re) || egrep(string: r[2], pattern: pass2_re)) )
      {
        if (isnull(ctrl_re) || egrep(string: r[1]+r[2], pattern: ctrl_re))
	{
	  xt = strcat('\nNessus was able to exploit the issue using the following URL :\n\n  ', build_url(port: port, qs: u));
	  if (report_verbosity > 1)
	  {
	    res = strcat(r[0], r[1], '\r\n', r[2]);
	    z = NULL;
	    if (! isnull(pass_str))
	      z = extract_pattern_from_resp(string: res, pattern: 'ST:'+pass_str);
	    if (! z && ! isnull(pass_re))
	      z = extract_pattern_from_resp(string: res, pattern: 'RE:'+pass_re);
	    if (z)
	      xt = strcat(xt, '\n\nIt produced the following response :\n\n', z, '\n');
	  }

	  if (! silent)
	    if (!low_risk && ! high_risk)
	      security_warning(port: port, extra: xt);
	    else
            {
              if (low_risk) security_note(port: port, extra: xt);
	      else security_hole(port: port, extra: xt);
            }
	  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	  set_kb_item(name: "/tmp/XSS/"+port+item, value: TRUE);
	  if (sql_injection)
	    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	  return 1;
	}
      }
    }
  }
  return 0;
}

################################################

# Same as check_win_dir_trav(), but with KA support
function check_win_dir_trav(port, url, exit_on_fail)
{
  local_var	v;

  v = http_send_recv3(port:port, method: 'GET', item: url, exit_on_fail: exit_on_fail);
  if (isnull(v)) return NULL;

  if ( "; for 16-bit app support" >< v[2] ||
       # This happens in pathological cases
       "; for 16-bit app support" >< v[1] ||
       "; for 16-bit app support" >< v[0] )
    return 1;
  return 0;
}


function is_cgi_installed3(item, port, exit_on_fail)
{
 local_var v, v2, no404, dir, slash, dirs, banner, u, u2;

 if (get_kb_item("Settings/disable_cgi_scanning"))  return 0;

# banner = get_http_banner(port: port);

 if (item[0] != "/")
 {
  dirs = cgi_dirs();
  slash = "/";
 }
 else
 {
  dirs = make_list("");
  slash = "";
 }
 
 no404 = get_kb_item(strcat("www/no404/", port));
 if (strlen(no404) >= 1) return NULL;

 foreach dir (dirs)
 {
   u = dir + slash + item;
   v = http_send_recv3(port: port, method: 'GET', item: u, exit_on_fail: exit_on_fail);
   if (isnull(v)) return NULL;
   if(v[0] =~ '^HTTP/[01]\\.[0-9] +200 ')
   {
     u2 = ereg_replace(pattern:"^(.*)/([^/]*)$", replace:"\1/is_cgi_installed3_\2", string:u);
     v2 = http_send_recv3(port: port, method: 'GET', item: u2, exit_on_fail: exit_on_fail);
     if (isnull(v2)) return NULL;
     if(v2[0] =~ '^HTTP/[01]\\.[0-9] +200 ')
     {
       return 0;
     }
     else
     {
       set_kb_item(name: "www/"+port+"/installed_cgi", value: u);
       set_kb_item(name: "www/"+port+"/get_cgi"+u, value: strcat(v[0], v[1], '\r\n', v[2]));
       return(1);
     }
    }
 }
 return 0;
}

#
  
function get_http_page(port, url, redirect)
{
  local_var	r, u, v, i, l, seen_loc, n;

  if (isnull(redirect))
    n = 32;
  else if (redirect <= 0)
    n = 1;
  else
    n = redirect + 1;

  seen_loc = make_list();
  u = url;
  for (i = 0; i < n; i ++)	# Limited iterations to avoid traps
  {
    seen_loc[u] = 1;
    r = http_send_recv3(port: port, method: 'GET', item: u);
    if (isnull(r)) return NULL;
    if (r[0] =~ '^HTTP/[01]\\.[01] +30[0-9] ')
    {
      v = eregmatch(pattern: '\r\nLocation: *([^ \t\r\n]+)[ \t]*[\r\n]',
		string: '\r\n'+r[1], icase: 1);
      if (isnull(v)) return NULL;	# Big problem
      l = v[1];
      if (seen_loc[l]) return NULL;
      seen_loc[l] = 1;
    }
    else if (r[0] =~ '^HTTP/[01]\\.[01] +200 ')
      return r[2];
    else	# Code 4xx or 5xx
      return NULL;
  }
  # Loop?
  return NULL;
}

function http_get_cache(port, item, cookies, exit_on_fail)
{
 local_var r, full, headers, h;

 r = get_kb_item("Cache/" + port + "/URL_" + item );
 if (r)
 {
   if (cookies)
   {
     headers = r - strstr(r, '\r\n\r\n');
     headers = egrep(string: headers, pattern: "^Set-Cookie2?:", icase: 1);
     foreach h (split(headers, keep: 0))
       parse_setcookie_header(header: h);
   }
   return r;
 }
 r = http_send_recv3(port: port, method: 'GET', item: item, exit_on_fail: exit_on_fail);
 if (isnull(r)) return NULL;
 full = strcat(r[0], r[1], '\r\n', r[2]);
   replace_kb_item(name:"Cache/" + port + "/URL_" + item, value: full);
 return full;
}

function http_check_remote_code(default_port, extra_dirs, unique_dir, check_request, extra_check, check_result, command, description, port, embedded, xss, sql_inject, warning)
{
 local_var list, txt_result, txt_desc, extra, dir, buf, v, uri, output;
 if ( get_kb_item("Settings/disable_cgi_scanning") )  exit(0, "CGI scanning is disabled");

 if (unique_dir)
   list = make_list (unique_dir);
 else
 {
  if (!isnull(extra_dirs))
    list = make_list (cgi_dirs(), extra_dirs);
  else
    list = make_list (cgi_dirs());
 }

 if ( ! port )
 {
 if (default_port)
   port = get_http_port(default:default_port, embedded: embedded);
 else
   port = get_http_port(default:80, embedded: embedded); 
 }

 foreach dir (list)
 {
   uri = strcat(dir, check_request);
   v = http_send_recv3(port:port, method: 'GET', item: uri, exit_on_fail: 1);
   # Should I egrep the headers too?
   txt_result = egrep(pattern:check_result, string: v[2]);
   if (extra_check)
   {
    extra = 0;
    if (egrep(pattern:extra_check, string: v[2]))
      extra = 1;
   }
   else
     extra = 1;

   if (txt_result && extra)
   {
      output = "
It was possible to execute the command '" + command + "' on the remote host
by requesting the following URL :

"+build_url(qs:uri, port:port)+'\n';
      if (report_verbosity > 1)
      {
        output += '
which produces the following output :

' + txt_result;
      }
    if (description)
    {
      txt_desc = description + 
"

Plugin output :
" + output;
      if (warning)
        security_warning(port:port, data:txt_desc);
      else
    security_hole (port:port, data:txt_desc);
    }
    else
    {
      if (warning)
        security_warning(port:port, extra: output);
      else
        security_hole (port:port, extra: output);
    }
    if (xss) set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    if (sql_inject) set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit (0);
   }
 }
}

##
# 
# Attempts to exploit a directory traversal
#
# @param port The port the web server is listening on
# @param extra_dirs Any extra directories to test outside of cgi_dirs()
# @param unique_dir A specific directory to test.  If this is specified, extra_dirs is not used
# @param qs The request portion of the URL
# @param extrafile An extra file to attempt to retrieve besides win.ini or /etc/passwd
# @param extrapats A list of patterns to look for in requests for extrafile
# @param extra_sep Either AND or OR.  Specifies if all or any of extrapats needs to be found
# @param extra_numdot The number of ../ to add to requested file.  Only needed if extrafile is specified
# @param anchor The anchor value if one is needed (ie %00 or \00)
# @param os The operating system to limit the test to.  If the value is not Windows, it is assumed to be a nix OS
# @param exit_on_fail Exit if there is a failure
# @return An array of vulnerable requests and the resulting content, or
#          0 if the host is not vulnerable
#         NULL if there was an error
##
function http_check_dir_traversal(port, extra_dirs, unique_dir, qs, extrafile, extrapats, extra_sep, extra_numdot, anchor, os, exit_on_fail)
{
  local_var list, dir, file, files, file_pat, file_pats;
  local_var found_file, exploit, contents, url_list, vuln_reqs;
  local_var url, res, vuln, i, success;

  if (unique_dir)
    list = make_list(unique_dir);
  else
  {
    if (!isnull(extra_dirs))
      list = make_list (cgi_dirs(), extra_dirs);
    else
      list = make_list (cgi_dirs());
  }

 # Create a list of files to request and patterns to look for
  files = make_list();
  if (os && report_paranoia < 2)
  {
    if ('Windows' >< os)
      files = make_list('/windows/win.ini', '/winnt/win.ini');
    else 
      files = make_list('/etc/passwd');
  }
  else files = make_list('/windows/win.ini', '/winnt/win.ini', '/etc/passwd');

  file_pats = make_array();
  file_pats['/etc/passwd'] = 'root:.*0:[01]:';
  file_pats['/winnt/win.ini'] = '^(\\[[A-Za-z]+\\]|^; for 16-bit app support|\\[MCI Extensions.BAK\\])';
  file_pats['/windows/win.ini'] = '^(\\[[A-Za-z]+\\]|^; for 16-bit app support|\\[MCI Extensions.BAK\\])';
 
  if (extrafile)
  {
    file_pats[extrafile] = make_list(extrapats);
  }

  # Send the request and check the output
  vuln_reqs = make_array();
  success = FALSE;
  foreach dir (list)
  {
    foreach file (files)
    {
      file_pat = file_pats[file];
      # Once we find a file that works, stick with it for subsequent tests
      if (found_file && file != found_file)
        continue;

      if (file[0] == '/')
        exploit = mult_str(str:"../", nb:12) + file;
      else
      {
        if (isnull(extra_numdot)) extra_numdot = 1;
        exploit = mult_str(str:"../", nb:extra_numdot) + file;
      }
      if (anchor) exploit += anchor;

      url = dir + qs + exploit;
      res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:exit_on_fail);
      if (isnull(res)) continue;
      success = TRUE;

      if (file[0] == '/')
      {
        if (egrep(pattern:file_pat, string:res[2]))
          vuln = TRUE;
      }
      else
      {
        if (extra_sep && (extra_sep != 'AND' && extra_sep != 'OR'))
          exit(1, 'Invalid value supplied for the separator');
        for (i=0; i< max_index(file_pat); i++)
        {
          # If the pattern is in the result, set vuln to TRUE.
          if (file_pat[i] >< res[2])
          {
            vuln = TRUE;
            # If the separator is OR, only one pattern needs to be found in the
            # result, so break out
            if (extra_sep == 'OR')
             break;

            continue;
          }
          # IF the separator is AND, all of the patterns need to be found.  If
          # a pattern is not found, make sure vuln is set to FALSE, then break out.
          # If we made it this far, it means the pattern wasn't found in the result
          if (extra_sep == 'AND')
          {
            vuln = FALSE;
            break;
          }
        }
      }

      # If vuln is TRUE, add the vulnerable request to the array
      if (vuln)
      {
        vuln_reqs['url'] = url;

        if (!contents)
        {
          found_file = file;

          contents = res[2];
          vuln_reqs['contents'] = contents;
          vuln_reqs['file'] = file;
          return vuln_reqs;
        }
      }
    }
  }
  if (!success) return NULL;
  return 0;
}

global_var __http_store_cnt;
__http_store_cnt = 0;
function http_store_dialog(port, req, resp, bufsent, bufrec)
{
  local_var	k1, k2;

  if (isnull(bufsent))
  {
    if (isnull(req))
      bufsent = http_last_sent_request();
    else
      bufsent = http_mk_buffer_from_req(req: req);
  }

  if (isnull(bufrec))
  {
    if (! isnull(resp))
    {
      bufrec = resp[0];
      if (! isnull(resp[1]))
      {
        bufrec = strcat(bufrec, resp[1]);
	if (! isnull(resp[2]))
	{
          bufrec = strcat(bufrec, '\r\n', resp[2]);
	}
      }
    }
  }

  # An imperfect protection against duplicated keys
  repeat
  {
    k1 = strcat("www/", port, "/", SCRIPT_NAME, "/request/", __http_store_cnt);
    k2 = strcat("www/", port, "/", SCRIPT_NAME, "/response/", __http_store_cnt);
    __http_store_cnt ++;
  }
  until (isnull(get_kb_list(k1)) && isnull(get_kb_list(k2)));

  set_kb_item(name: k1, value: bufsent);
  set_kb_item(name: k2, value: bufrec);
}

