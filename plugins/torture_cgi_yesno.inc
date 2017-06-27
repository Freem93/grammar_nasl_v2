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
# torture_cgi_yesno.inc
# $Revision: 1.27 $
# $Date: 2016/02/11 17:07:27 $
#

include("torture_cgi_names.inc");
include("torture_cgi_func.inc");

global_var	success, reports, posreply, posregex, postheaders;
global_var	port, poison_ok, poison_ko;
global_var	stop_at_first_flaw;
global_var	timed_out, url_count, test_arg_val;

# Answer to the good request is the first element, 
# answers to bogus requests come next.
global_var	req_resp_l, req_len_l;

global_var	cnx_errors;

function inject_poison(data, poison)
{
  local_var	j, val, u;

  if ("VALUE" >< poison)
  {
    j = stridx(data, '=');
    if (j < 0)
    {
      err_print("inject_poison: cannot find = in ", data);
      return NULL;
    }
    val = substr(data, j + 1);
    u = strcat(data, 
        str_replace(string: poison, find:"VALUE", replace: val));
    return u;
  }
  else
   return strcat(data, poison);
}

function test(meth, url, postdata, cgi, vul, poisoned_param)
{
  local_var	u, i, n, len, u1, req, act, dir, v, z, rep, d;
  local_var	uOK, dOK, flag, retry;
  local_var	cnt, j, val, RE_414, fpcgi, alea;
  local_var	r, rOK, rKO, errmsg;

  fpcgi = get_kb_item('www/'+port+'cgi-FP'+cgi);

  if (vul == "OP")
    RE_414 = "^HTTP/1\.[01] +(40[013]|41[34])";
  else
    RE_414 = NULL;

  if (excluded_RE && ereg(string: my_encode(url), pattern: excluded_RE, icase: 1))
    return -1;
  # This may be very slow but is necessary for some technology like ASP.NET
  dir = NULL;
  if (isnull(postdata))
    act = make_list(url);
  else
  {
    # Cleanly encoding the posted data is not necessary so far
    # postdata = urlencode(str: postdata, case_type: HEX_UPPERCASE);
    act = get_form_action_list(port: port, cgi: cgi);
    if (max_index(act) == 0)
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
    u = my_encode(url); u1 = u;
    if (excluded_RE && ereg(string: u, pattern: excluded_RE, icase: 1))
      continue;
    debug_print(level: 2, "M=", meth, " - U=", url, " - D=", postdata);

    # 1. Send the normal request
    r = http_send_get_post(item: u, port:port, method: meth, data: postdata, post_headers: postheaders);

    if (isnull(r))
    {
      errmsg = http_error_msg();
      set_kb_item(name: 'torture_CGI/error_msg/'+port+'/'+vul, value: errmsg);
      cnx_errors ++;
      debug_print('http_send_recv3=NULL port=', port, ' (', errmsg, ')\n');
      return 0;
    }

    if (! isnull(RE_414) && ereg(string: r[0], RE_414))
    { # The web server is protected against the attack
      debug_print('http_send_recv3(port=', port, ')= ', chomp(r[0]));
      return 0;
    }

    rOK = r;
    torture_cgi_audit_response(port: port, cgi: cgi, url: url, vul: vul, poisoned_param: poisoned_param, response: r, postdata: postdata);

    for (i = 0; ! isnull(poison_ok[i]); i ++)
    {
      # 2. send the request with an "OK" poison
      if (isnull(postdata))
      {
        u = inject_poison(data: url, poison: poison_ok[i]);
        if (isnull(u)) continue;
        u = my_encode(u);
        d = NULL;
        r  = http_send_recv3(item: u, port:port, method: meth);
      }
      else
      {
        d = inject_poison(data: postdata, poison: poison_ok[i]);
	if (isnull(d)) continue;
        r  = http_send_recv3(item: u, port:port, method: meth, 
	    data: d, add_headers: postheaders);
      }

      # anti FP
      if (isnull(r) && (report_paranoia < 2 || fpcgi))
      {
        errmsg = http_error_msg();
        debug_print('http_send_recv3(OK)=NULL port=', port, ' (', errmsg, ')\n');
	if (http_transient_error())
	{
        cnx_errors ++;
          set_kb_item(name: 'torture_CGI/error_msg/'+port+'/'+vul, value: errmsg);
	}
        continue;
      }

      if (! isnull(RE_414) && ereg(string: r[0], RE_414))
      { # The web server is protected against the attack
        debug_print('http_send_recv3(port=', port, ')= ', chomp(r[0]));
        return 0;
      }

      # We should get the same answer if there is an injection
      if (answers_differ(r1: rOK, r2: r)) continue;

      uOK = u; dOK = d;

      # 3. Send the request with a "KO" poison.
      if (isnull(postdata))
      {
        u = inject_poison(data: url, poison: poison_ko[i]);
	if (isnull(u)) continue;
	u = my_encode(u);
	d = NULL;
        r  = http_send_recv3(item: u, port:port, method: meth);
      }
      else
      {
        d = inject_poison(data: postdata, poison: poison_ko[i]);
	if (isnull(d)) continue;
        r  = http_send_recv3(item: u, port:port, method: meth, 
	    data: d, add_headers: postheaders);
      }

      if (! isnull(RE_414) && ereg(string: r[0], RE_414))
      { # The web server is protected against the attack
        debug_print('http_send_recv3(port=', port, ')= ', chomp(r[0]));
        return 0;
      }

      # anti FP
      if (isnull(r) && (report_paranoia < 2 || fpcgi))
      {
        errmsg = http_error_msg();
        debug_print('http_send_recv3(OK)=NULL port=', port, ' (', errmsg, ')\n');
	if (http_transient_error())
	{
        cnx_errors ++;
          set_kb_item(name: 'torture_CGI/error_msg/'+port+'/'+vul, value: errmsg);
	}
        continue;
      }

      # We should get a different answer this time
      z = answers_differ(r1: rOK, r2: r);
      if (! z) continue;
      req = http_last_sent_request();
      rKO = r;

      # Retry initial request to make sure that the page did not change 
      # so that we do not get an FP on a forum, for example.
      r = http_send_get_post(item: u1, port:port, method: meth, data: postdata, post_headers: postheaders);
    
      if (answers_differ(r1: rOK, r2: r))
      {
	torture_cgi_remember(anti_fp: 1, port: port, method: meth, request: req, url: u, response2: rOK, response: rKO, cgi: cgi, param: poisoned_param, vul: vul, report: rep, postdata: d);
	fpcgi = 1;
        continue;
      }

      if (report_paranoia < 2 || fpcgi)
      {
        flag = 1;
        for (retry = 1; retry <= 6 && flag; retry ++)
	{
	  sleep(retry);
	  alea = rand() & 1;

          # Retry the "OK" request
	  if (alea)
	  {
            r  = http_send_get_post(item: uOK, port:port, method: meth, data: dOK, post_headers: postheaders);
    
	    if (answers_differ(r1: r, r2: rOK))
      	    {
	      torture_cgi_remember(anti_fp: 1, port: port, method: meth, url: uOK, response: r, response2: r, cgi: cgi, param: poisoned_param, vul: vul, report: rep, postdata: dOK);
	      flag = 0; break;
	    }
	  }

          # Retry "KO" request in case it changed
          sleep(1);
 	  r  = http_send_get_post(item: u, port:port, method: meth, data: d, post_headers: postheaders);
	  if (answers_differ(r1: r, r2: rKO))
	  {
	    torture_cgi_remember(anti_fp: 1, port: port, method: meth, url: u, response: rKO, response2: r, cgi: cgi, param: poisoned_param, vul: vul, report: rep, postdata: d);
	    flag = 0; break;
	  }

	  # Retry the initial request
	  if (! alea)
	  {
	    r  = http_send_get_post(item: u1, port:port, method: meth, data: postdata, post_headers: postheaders);
	    if (answers_differ(r1: rOK, r2: r))
      	    {
	      torture_cgi_remember(anti_fp: 1, port: port, method: meth, url: u1, response: rOK, response2: r, cgi: cgi, param: poisoned_param, vul: vul, report: rep, postdata: postdata);
	      flag = 0; break;
	    }
	  }
	}	# retry loop

	# Retry the initial request one last time
	if (flag)
	{
	  sleep(3);
	  r = http_send_get_post(item: u1, port:port, method: meth, data: postdata, post_headers: postheaders);
	  if (answers_differ(r1: rOK, r2: r))
	  {
	    torture_cgi_remember(anti_fp: 1, port: port, method: meth, url: u1, response: rOK, response2: r, cgi: cgi, param: poisoned_param, vul: vul, report: rep, postdata: postdata);
	    flag = 0;
	  }
	}

	if (! flag)
	{
	  fpcgi = 1;
	  continue;
	}
      }	# anti-FP


	rep = compute_diff(r1: rOK, r2: rKO, idx: z);
	# Shorten buffer overflow requests
	if (vul[0] == "O")
	{
	  if ("XXXXXXX" >< u)
	  {
	    z = ereg_replace(string: u, pattern: "(XXXXXXXX*)", replace: "\1");
	    len = strlen(z);
  	    u = ereg_replace(string: u, pattern: "XXXX*XXX", replace: 
	      "XX[... "+ len+" bytes...]XX");
	    req = ereg_replace(string: req, pattern: "XXXX*XXX", replace: "XX[...]XX");
	  }
	  if ("0000000" >< u)
	  {
	    z = ereg_replace(string: u, pattern: "(00000000*)", replace: "\1");
	    len = strlen(z);
	    u = ereg_replace(string: u, pattern: "0000*000", replace: 
	      "00[... "+ len+" bytes...]00");
	    req = ereg_replace(string: req, pattern: "0000*000", replace: "00[...]00");
	  }
	}
        torture_cgi_remember(port: port, method: meth, request: req, url: u, response2: rOK, response: rKO, cgi: cgi, param: poisoned_param, vul: vul, report: rep, postdata: d);
	cnt ++;
	if (stop_at_first_flaw != "never") return 1;
    }
  }
  if (cnt > 0) return 1; else return -1;
}

function test1url(url, vul, poisoned_param)
{
  local_var	e, idx, len, cgi, mypostdata, meth_h;

  if (unixtime() > abort_time)
  {
    debug_print('Timeout! Aborted!\n');
    timed_out ++;
    return 0;
  }

  url_count ++;
  len = strlen(url);  
  idx = stridx(url, '?');
  if (idx > 0) cgi = substr(url, 0, idx - 1);
  else cgi = url;

  if (! try_all_meth) meth_h = get_cgi_methods(port:port, cgi:cgi);

  if (try_all_meth || meth_h["get"])
  {
  e = test(meth: "GET", url: url, cgi: cgi, vul: vul, poisoned_param: poisoned_param);
  if (e >= 0) return e;
  }

  if (try_all_meth || meth_h["post"])
  {
  mypostdata = substr(url, idx + 1);
  e = test(meth: 'POST', url: cgi, postdata:mypostdata, cgi: cgi, vul: vul, poisoned_param: poisoned_param);
  return e;
  }

  return -1;
}

function test_cgi_rec(url, param_l, data_ll, idx, var_idx, vul)
{
  local_var	i, d, u, e, cnt;

  if (isnull(param_l[idx]))
    return test1url(url: url, vul: vul, poisoned_param: param_l[idx - 1]);

  d = data_ll[idx];
  if ( (test_arg_val == "all_pairs" || test_arg_val == "some_pairs") && var_idx > 0)
  {
    d = make_list(d[0]);
  }
  else
    var_idx = idx;

  cnt = 0;
  for (i = 0; ! isnull(d[i]); i ++)
  {
    if (idx > 0)
      u = strcat(url, "&", param_l[idx], '=', d[i]);
    else
      u = strcat(url, param_l[idx], '=', d[i]);
    e = test_cgi_rec(url: u, param_l: param_l, data_ll: data_ll, var_idx: var_idx, idx: idx + 1, vul: vul);
    if (e == 0) return 0;
    if (e > 0)
    {
      cnt ++;
      if (stop_at_first_flaw != "never") return e;
    }
  }
  if (cnt > 0) return 1; else return -1;
}

function test1cgi(cgi, param_l, data_ll, vul)
{
  local_var	i, d, p, e, n, cnt;

  n = max_index(param_l) - 1;
  e = -1; cnt = 0;
  for (i = 0; i <= n; i ++)
  {
    if ( report_paranoia < 2 && 
       	 torture_cgi_untestable_param(cgi: cgi, param: param_l[i]) )
    {
      continue;
    }

    if (already_known_flaw(port: port, cgi: cgi, vul: vul))
    {
      debug_print("test1cgi port=",port, " cgi=", cgi, " vul=", vul, " -- flaw has already been reported");
      return -1;
    }

    # move the poisoned parameter at the end of the list
    if (i < n)
    {
      p = param_l[i]; param_l[i] = param_l[n]; param_l[n] = p;
      d = data_ll[i]; data_ll[i] = data_ll[n]; data_ll[n] = d;
    }
    init_cookiejar();
    e = test_cgi_rec(url: strcat(cgi, "?"), param_l: param_l, data_ll: data_ll, var_idx: -1, idx: 0, vul: vul);
    # Here, restoring the lists is not needed
    if (! e) return 0;
    if (e > 0)
    {
      cnt ++;
      if (stop_at_first_flaw != "never" && stop_at_first_flaw != "param")
        return e;
    }
  }
  if (cnt > 0) return e; else return -1;
}

####

function torture_cgis_yesno(port, vul, exclude_cgi, exclude_injectable)
{
  local_var	report, cgi_l, cgibase, args_l, vrequest, n, arg, d, r, data;
  local_var	l, excluded_cgi_h;
  local_var	cgi_cnt, cgi_nb, errmsg;

  if (get_kb_item("www/"+port+"/no_web_app_tests")) return NULL;

  success = make_array(); reports = make_array();
  cnx_errors = 0;

  excluded_cgi_h = NULL;
  if (exclude_injectable)
  {
    l = get_cgi_list(port: port, injectable_only: INJECTABLE_TEXT);
    if (max_index(l) > 0)
    {
      excluded_cgi_h = make_array();
      foreach d (l) excluded_cgi_h[d] = 1;
    }
  }

  cgi_l = get_cgi_list(port: port);
  cgi_nb = max_index(cgi_l);
  if (cgi_nb == 0) return NULL;

  cgi_cnt = 0; 
  foreach cgibase (cgi_l)
  {
    cgi_cnt ++;
    if (! isnull(exclude_cgi) && 
        ereg(string: cgibase, pattern: exclude_cgi, icase: 1)) continue;

    if (! isnull(excluded_cgi_h) && excluded_cgi_h[cgibase]) continue;

    if (already_known_flaw(port: port, cgi: cgibase, vul: vul)) continue;

    http_reauthenticate_if_needed(port: port);

    args_l =  get_cgi_arg_list(port: port, cgi: cgibase);
    vrequest = strcat(cgibase,"?");
    n = 0;
    foreach arg (args_l)
    {
      # Add vuln arg to modify empty param seed value for Blind SQLi tests
      d = get_cgi_arg_val_list(port: port, cgi: cgibase, arg: arg, fill: 1, vuln: vul);
      if (test_arg_val == "single") d = make_list(d[0]);
      if (max_tested_values > 0) d = shrink_list(l: d, n: max_tested_values);
      data[n] = d; 
      arg = replace_cgi_1arg_token(port: port, arg: arg);
      if (n > 0)
        vrequest = strcat(vrequest, '&', arg, '=', d[0]);
      else
        vrequest = strcat(vrequest, arg, '=', d[0]);
      n ++;
    }

    r = http_send_recv3(method: 'GET', item: my_encode(vrequest), port:port);
    if (isnull(r))
    {
      errmsg = http_error_msg();
      debug_print('http_send_recv3(OK)=NULL port=', port, ' (', errmsg, ')\n');
      if (http_transient_error())
      {
      cnx_errors ++;
        set_kb_item(name: 'torture_CGI/error_msg/'+port+'/'+vul, value: errmsg);
      }
      break;
    }
    if (r[0] !~  "^HTTP/1\..* (200|302) ") continue;

    if (! test1cgi(cgi: cgibase, param_l: args_l, data_ll: data, vul: vul))
      break;

   # Avoid stop_scan_on_hang
   scanner_status(current: cgi_cnt, total: cgi_nb);
  }

  if (cnx_errors > 0)
    set_kb_item(name: "torture_CGI/errors/"+port+"/"+vul, value: cnx_errors);

  report = torture_cgi_build_report(port: port, url_h: success, vul: vul);

  if (timed_out)
    if (strlen(report) == 0)
      set_kb_item(name: "torture_CGI/timeout/"+port, value: vul);
    else
      set_kb_item(name: "torture_CGI/unfinished/"+port, value: vul);
  else
    set_kb_item( name:"torture_CGI/duration/"+port+"/"+vul, 
    		 value: unixtime() - start_time);

  debug_print(level:2, url_count, ' URL were tested on port ', port, ' (args=', test_arg_val, ')');

  return report;
}
