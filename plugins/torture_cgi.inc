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
# torture_cgi.inc
# $Revision: 1.65 $
# $Date: 2015/09/15 19:39:32 $
#

include("torture_cgi_names.inc");
include("torture_cgi_func.inc");
include("url_func.inc");

global_var	req_count, url_count, fp_count;
global_var	timed_out, postheaders, excluded_RE;
global_var	flaws_and_patterns, test_arg_val, try_hpp;
global_var	stop_at_first_flaw, success, reports, excluded_RE;
global_var	global_patterns;

global_var	testable_args;	# used for quick directory traversals.
global_var	seen_resp_md5;

function test(port, url, cgi, meth, postdata, pattern, headers_only, vul, head_part, whole_response, anti_fp, only_content, follow_redirect, poisoned_param, ignore_duplicates)
{
  local_var r, k, rep, retry, act, v, dir, txt, z, cnt, f404, cs, chk;
  local_var add_url, add_postdata;
  local_var big;

  big = get_kb_list(strcat("www/", port, "/cgi-params", cgi, "/*"));
  add_url = add_postdata = NULL;
  if ( cgi =~ "\.(aspx|php|jsp)" )
  {
   foreach k ( make_list("__SCROLLPOSITIONX", "__SCROLLPOSITIONY", "__VIEWSTATE", "__VIEWSTATEENCRYPTED", "__VIEWSTATEGENERATOR", "__VIEWSTATEFIELDCOUNT", "__LASTFOCUS", "__PREVIOUSPAGE", "__EVENTVALIDATION", "__EVENTARGUMENT", "__EVENTTARGET", "Qform__FormState", "com.sun.faces.VIEW") )
   {
    if ( !isnull(big[strcat("www/", port, "/cgi-params", cgi, "/", k)] ) )
    {
    v = get_kb_list(strcat("www/", port, "/cgi-params", cgi, "/", k));
    if ( !isnull(v) )
    {
     v = make_list(v);
     v = v[0];
     if ( meth == "get" )
     {
     if ( strcat(k, "=") >!< url ) 
       {
     	        debug_print(level:2, "APPENDING ", k, " TO LIST v(", v, ") (G)\n");
		add_url += strcat("&", k, "=", urlencode(str:v));
       }
       else debug_print(level:2, "NOT APPENDING ", k, " TO LIST v(", v, ") (G)\n");
     }
     else
     {
     if ( strcat(k, "=") >!< postdata ) {
     	        	debug_print(level:2, "APPENDING ", k, " TO LIST v(", v, ") (P)\n");
			add_postdata += strcat("&", k, "=", urlencode(str:v));
	 }
     	 else  debug_print(level:2, "NOT APPENDING ", k, " TO LIST v(", v, ") (P)\n");
     }
    }
   }
   }
  }

  url = my_encode(url);
  if (excluded_RE && ereg(string: url, pattern: excluded_RE, icase: 1))
      return -1;

  f404 = 0;
  if (follow_redirect > 0 || thorough_tests || report_paranoia > 1) f404 = 1;
  pattern = strcat(pattern);  # Avoid dirty warnings in debug_print
  debug_print(level: 3, meth, ' URL=', replace_unprintable_char(url), ' - pattern=', pattern, ' - port=', port, '\n');

  # This may be very slow but is necessary for some technology like ASP.NET
  dir = NULL;
  if (isnull(postdata))
    act = make_list(url);
  else
  {
    # Cleanly encoding the posted data is not necessary so far
    # postdata = urlencode(str: postdata, case_type: HEX_UPPERCASE);
    act = get_form_action_list(port: port, cgi: cgi);
    if (isnull(act))
      act = make_list(url);
    else
    {
      v = eregmatch(string: url, pattern: "^(.*/)[^/]*");
      if (! isnull(v))
        dir = v[1];
      else
      {
        err_print("Cannot extract base directory from ", url);
	dir = "/";
      }
      act = list_uniq(make_list(url, make_list(act)));
    }
  }

 cnt = 0;
 foreach url (act)
 {
  if (url[0] != "/") url = strcat(dir, url);
  debug_print(level: 2, "M=", meth, " - U=", url, " - D=", postdata);
  # The web app tests are very long, this increases the risk of network glitch 
  for (retry = 1; retry <= 3; retry ++)
  {
    if (isnull(postdata))
      r = http_send_recv3(port:port, method: meth, item: strcat(url, add_url), only_content: only_content, follow_redirect: follow_redirect, fetch404: f404);
    else
      r = http_send_recv3(port:port, method: meth, item: url, data: strcat(postdata, add_postdata), add_headers: postheaders, only_content: only_content, follow_redirect: follow_redirect, fetch404: f404);
    req_count ++;
    if (! isnull(r) || ! http_transient_error()) break;
    debug_print('http_send_recv3=NULL - retry=', retry, '\n');
    sleep(retry);
  }

  if (isnull(r))
  {
    debug_print('http_send_recv3=NULL - aborting\n');
    # if (cnt > 0) return 1; else return 0;
    return 0;
  }
  if (r[0] =~ "^HTTP/1\.[01] 400 ") debug_print("test(", url, ") = ", r[0]);

  # Ignore Tomcat /appdev/processes*.html and /docs/.*.html files
  if (ereg(
    pattern : "(/appdev/.*\.html|/docs/.*\.html)",
    string  : url,
    multiline :TRUE)
  )
  {
    if (ereg(
      pattern : "Tomcat",
      string  : r[2],
      icase   : TRUE,
      multiline : TRUE)
    ) continue;
  }

  torture_cgi_audit_response(port: port, cgi: cgi, url: url, response: r, vul: vul, poisoned_param: poisoned_param, postdata: postdata);

  if (report_paranoia < 2 && r[0] =~ "^HTTP/1\.[01] 30[12] " && vul[0] == "X")
  {
    debug_print(level:2, "XSS won't work on redirections (port=", port, ")");
    continue;    
  }

  # First filter
# chk = torture_cgi_response_pre_check(resp: r);
# if (chk > 0) continue;

  if (pattern == "EX")	# Extended global patterns
  {
    txt = sanitize_utf16(body: r[2], headers: r[1]);
    rep = extract_pattern_from_resp(pattern: pattern, 
    	response: mk_list_silent3(r[0], r[1], txt));
    txt = strcat(r[0], r[1], '\r\n', txt);
  }
  else if (headers_only)
  {
    rep = extract_pattern_from_resp(pattern: pattern, string:r[1]);
    txt = r[1];
  }
  else
  {
    # charset may be UTF-16LE or UTF-16
    txt = sanitize_utf16(body: r[2], headers: r[1]);

    if (head_part)
    {
      txt = http_head_part(html: txt);
      rep = extract_pattern_from_resp(pattern:pattern, string: txt);
    }
    else if (whole_response)
    {
      txt = strcat(r[0], r[1], '\r\n', txt);
      rep = extract_pattern_from_resp(pattern:pattern, string: txt);
    }
    else
      rep = extract_pattern_from_resp(pattern:pattern, string:txt);
  }
  if (rep)
  {
    if (ignore_duplicates)
    {
      cs = MD5(txt);
      if (seen_resp_md5[cs]) continue;
      seen_resp_md5[cs] = 1;
    }

    # Additional filter
    chk = torture_cgi_response_post_check(resp: r);
    if (chk > 0) continue;

    torture_cgi_remember(port: port, vul: vul, cgi: cgi, param: poisoned_param, method: meth, url: url, response: r, report: rep, postdata: postdata, anti_fp: anti_fp);
    if (stop_at_first_flaw != "never") return 1;
    cnt ++;
  }
 }	# foreach url (act)
 if (cnt > 0) return 1; else return -1;
}

function test1url(port, url, cgi, pattern, vul, head_part, whole_response, anti_fp, only_content, follow_redirect, poisoned_param, ignore_duplicates)
{
  local_var	e, headers, f, meth_h;
  local_var	idx, mypostdata;

  if (unixtime() > abort_time)
  {
    debug_print('Timeout! Aborted!\n');
    timed_out ++;
    return 0;
  }
  url_count ++;
  headers = 0; if (vul == "HI") headers = 1;

  if (! try_all_meth) meth_h = get_cgi_methods(port:port, cgi:cgi);

  e = -1;
  if (try_all_meth || meth_h["get"])
  {
  e = test(port:port, meth: "GET", cgi: cgi, url: url, pattern: pattern, vul:vul, headers_only: headers, head_part: head_part, whole_response: whole_response, anti_fp: anti_fp, only_content: only_content, follow_redirect: follow_redirect, poisoned_param: poisoned_param, ignore_duplicates: ignore_duplicates);
  if (e == 0) return 0;
  if (e > 0)
    if (stop_at_first_flaw != "never")
      return e;
  }

  f = e;
  if (try_all_meth || meth_h["post"])
  {
    idx = stridx(url, '?');
    if (idx >= 0)
    {
      cgi = substr(url, 0, idx - 1);
      mypostdata = substr(url, idx + 1);
      e = test(port: port, meth: 'POST', cgi: cgi, url: cgi, postdata:mypostdata, pattern: pattern, vul: vul, headers_only: headers, head_part: head_part, whole_response: whole_response, only_content: only_content, follow_redirect: follow_redirect, poisoned_param: poisoned_param, ignore_duplicates: ignore_duplicates);
      if (e > 0) return e;
      if (e == 0 && f < 0) return 0;
    }
    }
  return f;
}

function test_cgi_rec(port, cgi, url, param_l, data_ll, idx, poison_idx, var_idx, pattern, vul, head_part, whole_response, anti_fp, only_content, follow_redirect, ignore_duplicates)
{
  local_var	i, j, d, u, u1, e, fl, pat, val, head, v, filename;
  local_var	fp_flag, cnt, poison;

  debug_print(level: 3, "test_cgi_rec: port=", port, " url=", url, " param_l=", param_l, " idx=", idx, " poison_idx=", poison_idx, " var_idx=", var_idx);

  if (isnull(param_l[idx]))	# last argument
  {
    e = test1url(port: port, cgi: cgi, url: url, vul: vul, pattern: pattern,
      poisoned_param: param_l[poison_idx],
      ignore_duplicates: ignore_duplicates,
      head_part: head_part, whole_response: whole_response, anti_fp: anti_fp, only_content: only_content, follow_redirect: follow_redirect);
    if (vul == "YY" && e > 0)
    {
      set_kb_item(name: "www/"+port+"/injectable/cgi", value: cgi);
      set_kb_item(name: "www/"+port+"/injectable/cgi-arg"+cgi, value: param_l[poison_idx]);      
    }
    if (vul == "YZ" && e > 0)
    {
      set_kb_item(name: "www/"+port+"/html_injection/cgi", value: cgi);
      set_kb_item(name: "www/"+port+"/html_injection/cgi-arg"+cgi, value: param_l[poison_idx]);      
    }
    return e;
  }

  d = data_ll[idx];
  if ((test_arg_val == "all_pairs" || test_arg_val == "some_pairs") && var_idx > 0)
    d = make_list(d[0]);

  debug_print(level: 3, "test_cgi_rec: d=", d);

  if (idx == poison_idx)
  {
# If the report_paranoia value is changed, scripts which test 2nd order
# SQL injections or persistent XSS may have to be updated.
#
# As torture_cgi_sql_injection.nasl is prone to FPs if the web application is
# broken and sends "spontaneous" SQL error messages, the FP detector is 
# enabled by default for such tests. The risk of FN is negligible as these 
# errors will be reported by torture_cgi_sql_error_msg2.nasl anyway.
    if (report_paranoia < 1 || anti_fp ||
        (report_paranoia < 2 && ! isnull(global_patterns)) )
    {
      pat = NULL;
      foreach fl(keys(flaws_and_patterns))
      {
        if (pat == flaws_and_patterns[fl]) continue;
	pat = flaws_and_patterns[fl];
        head_part = ("meta" >< fl && "http-equiv" >< fl);
        for (i = 0; ! isnull(d[i]); i ++)
        {
	  if (idx > 0)
	    u = strcat(url, "&", param_l[idx], '=', d[i]);
	  else
	    u = strcat(url, param_l[idx], '=', d[i]);
          e = test_cgi_rec(port:port, cgi: cgi, url: u, param_l: param_l, data_ll: data_ll, idx: idx + 1, poison_idx: poison_idx, var_idx: var_idx, pattern: pat, vul:vul, head_part: head_part, whole_response: whole_response, anti_fp: 1, only_content: only_content, follow_redirect: follow_redirect, ignore_duplicates: ignore_duplicates);
          if (e > 0) return -1;
          if (e == 0) return 0;
# Only test one value for each parameter, unless we are ready to lose time
	  if (! thorough_tests) break;
	}
      }
    }

    cnt = 0;
    foreach fl(keys(flaws_and_patterns))
    {
      head_part = ("meta" >< fl && "http-equiv" >< fl);
      pat = flaws_and_patterns[fl];
      for (i = 0; ! isnull(d[i]); i ++)
      {
       if (idx > 0) u1 = strcat(url, "&"); else u1 = url;
       if ("VALUE"  >< fl)
       {
         if (max_index(d) > 0) val = d[0];
	 else val = "foobar";
 	 poison = str_replace(string: fl, find:"VALUE", replace:val);
       }
       else
       {
         if (i > 0) continue;
         if ("FILENAME" >< fl)
         {
           v = eregmatch(string: cgi, pattern: "/([^/]+)$");
	   if (isnull(v))
	     filename = cgi;
  	   else
	     filename = v[1];
	   poison = str_replace(string: fl, find:"FILENAME", replace: filename);
         }
         else
           poison = fl;
       }
       u = strcat(u1, param_l[idx], '=', poison);

       e = test_cgi_rec(port:port, cgi: cgi, url: u, param_l: param_l, data_ll: data_ll, idx: idx + 1, poison_idx: poison_idx, var_idx: var_idx, pattern: pat, vul:vul, head_part: head_part, whole_response: whole_response, only_content: only_content, follow_redirect: follow_redirect, ignore_duplicates: ignore_duplicates);
       if (e == 0) return 0;
       if (e > 0)
       {
         cnt ++;
	 if (stop_at_first_flaw != "never") return e;
       }

       # HTTP Parameter Pollution
       if (try_hpp && max_index(d) > 0)
       {
         val = d[0];
	 # Real value first, attack after
	 u = strcat(u1, param_l[idx], '=', val, '&', param_l[idx], '=', poison);
	 e = test_cgi_rec(port:port, cgi: cgi, url: u, param_l: param_l, data_ll: data_ll, idx: idx + 1, poison_idx: poison_idx, var_idx: var_idx, pattern: pat, vul:vul, head_part: head_part, whole_response: whole_response, only_content: only_content, follow_redirect: follow_redirect, ignore_duplicates: ignore_duplicates);
         if (e >= 0) return e;
	 # Attack first, real value after
	 u = strcat(u1, param_l[idx], '=', poison, '&', param_l[idx], '=', val);
	 e = test_cgi_rec(port:port, cgi: cgi, url: u, param_l: param_l, data_ll: data_ll, idx: idx + 1, poison_idx: poison_idx, var_idx: var_idx, pattern: pat, vul:vul, head_part: head_part, whole_response: whole_response, only_content: only_content, follow_redirect: follow_redirect, ignore_duplicates: ignore_duplicates);
         if (e == 0) return 0;
	 if (e > 0)
	 {
	   cnt ++;
	   if (stop_at_first_flaw != "never") return e;
	 }
       }
      }
     }
  }
  else
    for (i = 0; ! isnull(d[i]); i ++)
    {
      if (idx > 0)
        u = strcat(url, "&", param_l[idx], '=', d[i]);
      else
        u = strcat(url, param_l[idx], '=', d[i]);
      if (var_idx < 0 && idx != poison_idx && i > 0) var_idx = idx;
      e = test_cgi_rec(port:port, cgi: cgi, url: u, param_l: param_l, data_ll: data_ll, idx: idx + 1, poison_idx: poison_idx, var_idx: var_idx, pattern: pattern, vul:vul, head_part: head_part, whole_response: whole_response, anti_fp: anti_fp, only_content: only_content, follow_redirect: follow_redirect, ignore_duplicates: ignore_duplicates);
      if (e == 0) return 0;
      if (e > 0)
      {
        cnt ++;
	if (stop_at_first_flaw != "never") return e;
      }
    }
  if (cnt > 0) return 1; else return -1;
}


function test1cgi(port, cgi, param_l, data_ll, vul, only_content, follow_redirect, ignore_duplicates)
{
  local_var	i, e, wr, cnt;

  debug_print(level:2, "test1cgi: port=", port, " cgi=", cgi, " vul=", vul, " param_l=", param_l);

  wr = 0;
  if (vul[0] == "S") wr = 1;	# Look for SQLi in the whole response
  if (vul[0] == "X") wr = 0;	# Look for XSS in the body only

  cnt = 0;
  for (i = 0; ! isnull(param_l[i]); i ++)
  {
    if (! isnull(testable_args) && ! testable_args[strcat(cgi, "/", param_l[i])])
    {
      debug_print("Skipping untestable argument. port=", port, " cgi=", cgi, " param=", param_l[i]);
      continue;
    }

    if ( report_paranoia < 2 && 
       	 torture_cgi_untestable_param(cgi: cgi, param: param_l[i]) )
    {
      debug_print(level: 2, "Skipping untestable argument ", param_l[i]);
      continue;
    }

    if (already_known_flaw(port: port, cgi: cgi, vul: vul))
    {
      debug_print("test1cgi port=",port, " cgi=", cgi, " vul=", vul, " -- flaw has already been reported");
      return -1;
    }

    init_cookiejar();
    e = test_cgi_rec(port:port, cgi: cgi, url: strcat(cgi, "?"), param_l: param_l, data_ll: data_ll, idx: 0, vul:vul, poison_idx: i, var_idx: -1, head_part: 0, whole_response: wr, only_content: only_content, follow_redirect: follow_redirect, ignore_duplicates: ignore_duplicates);
    if (e == 0) return 0;
    if (e > 0)
    {
      cnt ++;
      if (stop_at_first_flaw != "never" && stop_at_first_flaw != "param") return e;
    }
  }
  if (cnt > 0) return 1; else return -1;
}

####

# ext_l is a list of extensions that will be attacked even if they were not 
# properly identified as CGIs.
function torture_cgis(port, vul, exclude_cgi, only_content, injectable_only, follow_redirect, ignore_duplicates, ext_l)
{
  local_var	cgi_l, cgi_name, args_l, arg, r, num_args, d, vals_l, e, z;
  local_var	report, cnx_errors, i, max_cnx_errors;
  local_var	cgi_cnt, cgi_nb, cgi_h, l, errmsg;
  local_var 	cgi_num_args, idx, cgi_array;

  if (get_kb_item("www/"+port+"/no_web_app_tests"))
  {
    debug_print("torture_cgis: web app tests are disabled on port ", port);
    return NULL;
  }

  cgi_l = get_cgi_list(port: port, injectable_only: injectable_only);
  if (max_index(cgi_l) == 0)
  {
     debug_print("torture_cgis: no CGI on port "+port);
     return NULL;
  }

  timed_out = 0;
  success = make_array();
  reports = make_array();
  cnx_errors = 0; max_cnx_errors = 32;

  cgi_cnt = 0; cgi_nb = max_index(cgi_l);
  if (! isnull(ext_l))
  {
    cgi_h = make_array();
    foreach cgi_name (cgi_l) cgi_h[cgi_name] = 1;
    foreach e (ext_l)
    {
      l = get_kb_list(strcat("www/", port, "/content/extensions/", e));
      if (isnull(l)) continue;
      foreach cgi_name (make_list(l))
        if (! cgi_h[cgi_name])
	{
	  cgi_l[cgi_nb ++] = cgi_name;
	  cgi_h[cgi_name] = 1;
	}
    }
  }
  cgi_nb --;
  cgi_num_args = make_array();
  foreach cgi_name (cgi_l)
  {
    args_l = get_cgi_arg_list(port: port, cgi: cgi_name, injectable_only: injectable_only);
    idx = string(max_index(args_l));
    
    # Try the login forms first
    if ( "login" >< tolower(cgi_name) ) idx = "0";
    if ( isnull(cgi_num_args[idx] ) )
    	cgi_num_args[idx] = make_list();

    if ( "login" >< tolower(cgi_name) ) 
    	cgi_num_args[idx] = make_list( cgi_name, cgi_num_args[idx]);
    else
    	cgi_num_args[idx] = make_list( cgi_num_args[idx], cgi_name);
  }

  cgi_l = make_list();
  foreach cgi_array ( numsort(keys(cgi_num_args) ) )
  { 
   foreach cgi_name ( cgi_num_args[cgi_array] )
	cgi_l[max_index(cgi_l)] = cgi_name;
  }

  foreach cgi_name (cgi_l)
  {
    cgi_cnt ++;
    if (! isnull(exclude_cgi) && 
        ereg(string: cgi_name, pattern: exclude_cgi, icase: 1)) continue;
    if (excluded_RE && '$' >!< excluded_RE && ereg(string: cgi_name, pattern: excluded_RE, icase: 1))
      continue;
    if (already_known_flaw(port: port, cgi: cgi_name, vul: vul)) continue;
    # Free memory & re-initialize list of known responses
    if (ignore_duplicates) seen_resp_md5 = make_array();
 
    num_args = 0;

    args_l = get_cgi_arg_list(port: port, cgi: cgi_name, injectable_only: injectable_only);
    foreach arg (args_l)
    {
      d = get_cgi_arg_val_list(port: port, cgi: cgi_name, arg: arg, fill: 1);
      if (test_arg_val == "single") d = make_list(d[0]);
      if (max_tested_values > 0) d = shrink_list(l: d, n: max_tested_values);
      vals_l[num_args ++] = d;
    }
    args_l = replace_cgi_args_token(port: port, args_list: args_l, max_tokens: 1);
    e = -1;
    #### Try incomplete URIs first - this should be quicker ####
    if (max_index(args_l) > 1)
    {
      for (i = 0; args_l[i]; i ++)
      {
        if (! isnull(testable_args) && ! testable_args[strcat(cgi_name, "/", args_l[i])])
    	{
      	  debug_print(level:2, "Skipping untestable argument. port=", port, " cgi=", cgi_name, " param=", args_l[i]);
      	  continue;
    	}

        z = make_list();
	z[0] = vals_l[i];
	http_reauthenticate_if_needed(port: port);
        e = test1cgi(port:port, cgi: cgi_name, param_l: make_list(args_l[i]), data_ll: z, vul: vul, only_content: only_content, follow_redirect: follow_redirect, ignore_duplicates: ignore_duplicates);
	z = NULL;
	if (e == 0)
	{
	  if (! timed_out)
            debug_print("Server did not answer - CGI = ", cgi_name, "\n");
	  break;
	}

        if (e > 0)
        {
          if (vul[0] == "X") set_kb_item(name: "/tmp/XSS/"+port+"/"+cgi_name, value: TRUE);
          if (stop_at_first_flaw != "never" && stop_at_first_flaw != "param")
	    break;
        }
      }
    }

    if (timed_out) break;

    if (e > 0)
      if (stop_at_first_flaw == "port") break;
      else if (stop_at_first_flaw == "CGI") continue;

   http_reauthenticate_if_needed(port: port);
   e = test1cgi(port:port, cgi: cgi_name, param_l: args_l, data_ll: vals_l, vul: vul, only_content: only_content, follow_redirect: follow_redirect, ignore_duplicates: ignore_duplicates);
   if (timed_out) break;
  if (e == 0)
  {
    errmsg = http_error_msg();
    if (http_transient_error())
    {
      set_kb_item(name: 'torture_CGI/error_msg/'+port+'/'+vul, value: errmsg);
      ++ cnx_errors;
    }
    if (cnx_errors > max_cnx_errors)
    {
      debug_print('Too many failures - CGI = ', cgi_name, ' (', errmsg, ')\n');
      break;
    }
    else
      debug_print('Server did not answer - CGI = ', cgi_name, ' (', errmsg, ')\n');
   }

   if (e > 0)
   {
     if (vul[0] == "X") set_kb_item(name: "/tmp/XSS/"+port+"/"+cgi_name, value: TRUE);
     if (stop_at_first_flaw == "port") break;
   }
   # Avoid stop_scan_on_hang
   scanner_status(current: cgi_cnt, total: cgi_nb);
  }

  if (cnx_errors > 0)
    set_kb_item(name: "torture_CGI/errors/"+port+"/"+vul, value: cnx_errors);

  report = torture_cgi_build_report(port: port, url_h: success, vul: vul);

  if (timed_out)
  {
    if (!report)
      set_kb_item(name: "torture_CGI/timeout/"+port, value: vul);
    else
      set_kb_item(name: "torture_CGI/unfinished/"+port, value: vul);
  }
  else
    set_kb_item( name:"torture_CGI/duration/"+port+"/"+vul, 
    		 value: unixtime() - start_time);

  debug_print(level:2, url_count, ' URL were tested on port ', port, ' (args=', test_arg_val, ')');
  if (req_count)
    debug_print(level:2, req_count, ' requests were sent on port ', port, ' (args=', test_arg_val, ')');
  if (fp_count)
    debug_print(level:2, fp_count, ' FP were avoided on port ', port, '\n');
  return report;
}
