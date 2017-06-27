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
# torture_cgi_delay.inc
# $Revision: 1.28 $
#

include("torture_cgi_names.inc");
include("torture_cgi_func.inc");


global_var	success, reports, posreply, posregex, postheaders;
global_var	port, poison, t0;
global_var	excluded_RE, req_count, _fibo_delay;
global_var	cnx_errors;

_fibo_delay = make_list(3, 5, 8, 13, 21);
_default_delay = 6;	# Use a different value

function test(meth, url, postdata, cgi, int_param, vul, poisoned_param)
{
  local_var	u, d, r, r1, r2, i, n, len, req, act, dir, v, rep, nd;
  local_var	delay, del, p, t1, t2, flag, cnt;
  local_var	dt, dtPrev, delPrev, errmsg, prev_timeout, prev_incr_flag;


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
    if (excluded_RE && ereg(string: my_encode(url), pattern: excluded_RE, icase: 1))
      continue;
    debug_print(level: 2, "M=", meth, " - U=", url, " - D=", postdata);

    for (i = 0; ! isnull(poison[i]); i ++)
    {
      # Currently, all poisons use a variable delay but this may change in
      # the future and be a source of False Positive.
      if ("DeLaY" >!< poison[i] && report_paranoia < 2) continue;

      # Optimization
      if (! thorough_tests && vul[0] == 'S')
        if (! int_param && substr(poison[i], 0, 0) != "'")
	{
          continue;
	}

      flag = 1; r1 = NULL;
      dtPrev = 0;
      delPrev = 0;
      for (nd = 0; flag && _fibo_delay[nd]; nd ++)
      {
        del = _fibo_delay[nd];
        if ("DeLaY" >< poison[i])
	{
	  delay = del;
          p = str_replace(string: poison[i], find: "DeLaY", replace: delay);
	}
	else
	{
	  delay = _default_delay;
	  p = poison[i];
	}
	# delay is doubled in case the request is duplicated
	prev_timeout = http_set_read_timeout(t0 + 2 * delay);
	prev_incr_flag = http_incr_timeout_on_err(0);
	t1 = unixtime();
        if (isnull(postdata))
        {
          u = my_encode(strcat(url, p)); d = NULL;
	  #debug_print(level: 2, ">> M=", meth, " - U=", u);
	  r = http_send_recv3(item: u, port:port, method: meth);
        }
        else
	{
	  u = url; d = my_encode(strcat(postdata, p));
	  #debug_print(level: 2, ">> M=", meth, " - U=", url, " - D=", d);
          r  = http_send_recv3(item: url, port:port, method: meth, 
	     data: d, add_headers: postheaders);
        }

        if (isnull(r))
	{
	  errmsg = http_error_msg();
	  debug_print("Read error ', errmsg, ' (time=", dt, " / delay=", delay, ") on ", meth, " ", build_url(port: port, qs: url));
	  if (http_transient_error())
	  {
	  cnx_errors ++;
	    set_kb_item(name: 'torture_CGI/error_msg/'+port+'/'+vul, value: errmsg);
	  }
	  if (report_paranoia < 2)
	    return 0;
	  else
	    break;	# This could be a read timeout - skip to next form action
	}

	torture_cgi_audit_response(port: port, cgi: cgi, url: u, vul: vul, poisoned_param: poisoned_param, postdata: d, response: r);
	req_count ++;
	t2 = unixtime();
	dt = t2 - t1;
	if (dt < delay || (dt <= dtPrev && delay != _default_delay))
	{
	  flag = 0; break;
	}
	else
	{
	  r1 = r;
	}
	delPrev = delay;
	dtPrev = dt;
      }

      if (flag)
      {
        req = http_last_sent_request();
        if (report_paranoia < 2)
	{
	  http_set_read_timeout(prev_timeout);
	  http_incr_timeout_on_err(prev_incr_flag);

          # Double check
	  t1 = unixtime();
	  if (isnull(postdata))
            r2 = http_send_recv3(item: url, port:port, method: meth);
	  else
	    r2 = http_send_recv3(item: url, port:port, method: meth, data: postdata, add_headers: postheaders);
	  req_count ++;
	  if (isnull(r2))
	  {
	    errmsg = http_error_msg();
	    debug_print("No answer to normal request - this CGI is broken - url=", url, " postdata=", postdata, ' (', errmsg, ')');
	    if (http_transient_error())
	    {
  	      cnx_errors ++;
	      set_kb_item(name: 'torture_CGI/error_msg/'+port+'/'+vul, value: errmsg);
	    }
	    return 0;
	  }
	  t2 = unixtime();
	  dt = t2 - t1;
	  if (dt >= delay)
	  {
	    debug_print("A normal request took ", dt, "s - this CGI is broken - url=", url, " postdata=", postdata);
	    return -1;
	  }
	}
        torture_cgi_remember(port: port, method: meth, request: req, url: u, response: r1, response2: r2, cgi: cgi, param: poisoned_param, vul: vul, postdata: d);

	cnt ++;
	if (stop_at_first_flaw != "never") return 1;
      }
    }
  }
  if (cnt > 0) return 1; else return -1;
}

global_var	timed_out, url_count, req_count;

function test1url(url, vul, poisoned_param)
{
  local_var	e, idx, j, k, len, cgi, int_param, mypostdata;
  local_var	meth_h;

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

  if (! try_all_meth) meth_h = get_cgi_methods(port: port, cgi: cgi);

  # Optimization
  if (! thorough_tests)
   {
     int_param = 0;
     k = 0;
     for (j = idx + 1; j < len; j ++)
       if (url[j] == "=") k = j;
     if (k && substr(url, k + 1) =~ "^[0-9]+$") int_param = 1;
   }

  if (try_all_meth || meth_h["get"])
  {
  e = test(meth: "GET", url: url, cgi: cgi, int_param: int_param, vul: vul, poisoned_param: poisoned_param);
  if (e >= 0) return e;
  }

  if (try_all_meth || meth_h["post"])
  {
  mypostdata = substr(url, idx + 1);
  e = test(meth: 'POST', url: cgi, postdata:mypostdata, cgi: cgi, int_param: int_param, vul: vul, poisoned_param: poisoned_param);
  return e;
  }

  return -1;
}

global_var	test_arg_val;

function test_cgi_rec(url, param_l, data_ll, idx, var_idx, vul)
{
  local_var	i, d, u, e, flag, cnt;

  if (isnull(param_l[idx]))
    return test1url(url: url, vul: vul, poisoned_param: param_l[idx-1]);

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

global_var	stop_at_first_flaw;

function test1cgi(cgi, param_l, data_ll, vul)
{
  local_var	i, d, p, e, n, cnt;

  n = max_index(param_l) - 1;
  cnt = 0;
  for (i = 0; i <= n; i ++)
  {
    if (already_known_flaw(port: port, cgi: cgi, vul: vul))
    {
      debug_print("test1cgi port=",port, " cgi=", cgi, " vul=", vul, " -- flaw has already been reported");
      return -1;
    }

    if ( report_paranoia < 2 && 
       	 torture_cgi_untestable_param(cgi: cgi, param: param_l[i]) )
    {
      debug_print(level: 2, "Skipping untestable argument ", param_l[i]);
      continue;
    }

    # move the poisoned parameter at the end of the list
    if (i < n)
    {
      # We just keep one argument, to avoid a combinatorial explosion
      d = data_ll[i]; data_ll[i] = data_ll[n]; data_ll[n] = make_list(d[0]);
      p = param_l[i]; param_l[i] = param_l[n]; param_l[n] = p;
    }

    init_cookiejar();
    e = test_cgi_rec(url: strcat(cgi, "?"), param_l: param_l, data_ll: data_ll, var_idx: -1, idx: 0, vul: vul);

    if (! e) return 0;
    if (e > 0)
    {
      cnt ++;
      if (stop_at_first_flaw != "never" && stop_at_first_flaw != "param")
        return e;
    }

    # Restore the list
    if (i < n)
    {
      data_ll[n] = data_ll[i]; data_ll[i] = d;
      p = param_l[i]; param_l[i] = param_l[n]; param_l[n] = p;
    }
  }
  if (cnt > 0) return 1; else return -1;
}

global_var	test_arg_val, success, reports, timed_out, stop_at_first_flaw, excluded_RE;

function torture_cgi_delay(port, vul)
{
  local_var	cgi_l, r, cgi_name, arg, args_l, vrequest, n, d, param, data, report;
  local_var	cgi_nb, cgi_cnt, errmsg;

  if (get_kb_item("www/"+port+"/no_web_app_tests")) return NULL;

  if (! thorough_tests && stop_at_first_flaw == "port")
  {
    if (vul[0] == 'S' && get_kb_item('www/'+port+'/SQLInjection'))
      exit(0, strcat('A SQL injection was already found on port ', port));
  }

  success = make_array();
  reports = make_array();
  cnx_errors = 0;

  cgi_cnt = 0; cgi_nb = max_index(cgi_l) - 1;

  cgi_l = get_cgi_list(port: port);
  foreach cgi_name (cgi_l)
  {
    cgi_cnt ++;
    if (already_known_flaw(port: port, cgi: cgi_name, vul: vul))
    {
      debug_print(level: 2, "flaw similar to ", vul, " already known against ", build_url(port: port, qs: cgi_name));
      continue;
    }
    debug_print(level:2, "Attacking ", build_url(port: port, qs: cgi_name));

    http_reauthenticate_if_needed(port: port);

    vrequest = strcat(cgi_name,"?");
    n = 0;
    args_l = get_cgi_arg_list(port: port, cgi: cgi_name);
    foreach arg (args_l)
    {
      d = get_cgi_arg_val_list(port: port, cgi: cgi_name, arg: arg, fill: 1);
      if (test_arg_val == "single")  d = make_list(d[0]);
      if (max_tested_values > 0) d = shrink_list(l: d, n: max_tested_values);
      data[n] = d; 
      arg = replace_cgi_1arg_token(port: port, arg: arg);
      if (n > 0)
        vrequest = strcat(vrequest, '&', arg, '=', d[0]);
      else
        vrequest = strcat(vrequest, arg, '=', d[0]);
     n ++;
    }

    req_count ++;
    r = http_send_recv3(method: 'GET', item: my_encode(vrequest), port:port);
    if (isnull(r))
    {
      cnx_errors ++;
      break;	# Skip to next CGI
    }
    if (r[0] !~  "^HTTP/1\..* (200|302) ") continue;

    if (! test1cgi(cgi: cgi_name, param_l: args_l, data_ll: data, vul: vul)) break;
    # Avoid stop_scan_on_hang
    scanner_status(current: cgi_cnt, total: cgi_nb);
  }

  report = torture_cgi_build_report(port: port, url_h: success, vul: vul);
  if (strlen(report) > 0)
  {
    security_hole(port:port, extra: report);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  }

  if (timed_out)
    if (strlen(report) == 0)
      set_kb_item(name: "torture_CGI/timeout/"+port, value: vul);
    else
      set_kb_item(name: "torture_CGI/unfinished/"+port, value: vul);
  else
    set_kb_item( name:"torture_CGI/duration/"+port+"/"+vul, 
    		 value: unixtime() - start_time);

  if (cnx_errors > 0)
    set_kb_item(name: "torture_CGI/errors/"+port+"/"+vul, value: cnx_errors);

  debug_print(level:2, url_count, ' URL were tested on port ', port, ' (args=', test_arg_val, ')');
  debug_print(level:2, req_count, ' requests were sent on port ', port, ' (args=', test_arg_val, ')');
}
