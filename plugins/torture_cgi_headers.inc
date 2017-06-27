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
# torture_cgi_headers.inc
# $Revision: 1.24 $
# $Date: 2014/03/12 12:34:52 $
#

include("torture_cgi_names.inc");
include("torture_cgi_func.inc");

global_var	unsafe_urls, reports, port;

#######

url_count = 0;

global_var	timed_out;

function test1url(url, vul)
{
  local_var	e, cnt;
  local_var	idx, len, cgi, mypostdata, meth_h;

  if (unixtime() > abort_time)
  {
    timed_out ++;
    debug_print('Timeout! Aborted!\n');
    return 0;
  }
  url_count ++;

  len = strlen(url);
  cnt = 0;
  idx = stridx(url, '?');
  if (idx > 0)
    cgi = substr(url, 0, idx - 1);
  else if (idx < 0)
    cgi = url;
  else
    cgi = '';
  
  if (! try_all_meth) meth_h = get_cgi_methods(port:port, cgi:cgi);
  
  if (try_all_meth || meth_h["get"])
  {
      # When all_pairs and all_combinations are implemented, this request will
      # have to be move elsewhere.
      e = test(meth: "GET", url: cgi, cgi: cgi, vul: vul);
      if (e == 0) return 0;
      if (e > 0)
      {
        cnt ++;
	if (stop_at_first_flaw != "never")
          return e;
      }

      if (url != cgi)
      {
        e = test(meth: "GET", url: url, cgi: cgi, vul: vul);
        if (e == 0) return 0;
        if (e > 0)
        {
          cnt ++;
	  if (stop_at_first_flaw != "never")
            return e;
        }
      }
  }

  if (try_all_meth || meth_h["post"])
      {
        mypostdata = substr(url, idx + 1);
        e = test(meth: 'POST', url: cgi, postdata:mypostdata, cgi: cgi, vul: vul);
	if (e == 0) return 0;
	if (e > 0)
	{
	  cnt ++;
	  if (stop_at_first_flaw != "never")
            return e;
	}
      }

  if (cnt > 0) return 1; else return -1;
}

##############

global_var	port;

function reload_cookie_jars()
{
  local_var	cl;

  init_cookiejar(); load_cookiejar(jar: "webmirror-"+port);
  cl = get_http_cookie_keys();
  if (isnull(cl) || max_index(cl) == 0)
  {
    debug_print("reload_cookie_jars(port=", port, "): no cookie!\n");
    return 0;
  }
  return 1;
}

# ext_l is a list of extensions that will be attacked even if they were not 
# properly identified as CGIs.
function run_injection_hdr(vul, ext_l)
{
  local_var	cnx_errors, max_cnx_errors, cgi_l, cgi_name, args_l, arg, r;
  local_var	parameters, vrequest, n, d, e, report, ext, i, errmsg;

  if (vul[0] == "S")
  {
    if (! thorough_tests && stop_at_first_flaw == "port" && get_kb_item('www/'+port+'/SQLInjection'))
      exit(0, strcat('A SQL injection was already found on port ', port));
  }

  if (vul[0] == "X")
  {
    if (! thorough_tests && stop_at_first_flaw == "port" && get_kb_item('www/'+port+'/XSS'))
      exit(0, strcat('A XSS was already found on port ', port));
  }


  unsafe_urls = make_array();

  cnx_errors = 0; max_cnx_errors = 32;

 if (! isnull(ext_l))
  foreach ext (ext_l)
  {
    if (timed_out) break;
    http_reauthenticate_if_needed(port: port);
    cgi_l = get_kb_list(strcat("www/", port, "/content/extensions/", ext));
    if (isnull(cgi_l)) continue;
    cgi_l = make_list(cgi_l);
    foreach cgi_name (cgi_l)
    {
      if (timed_out) break;
      if (excluded_RE && '$' >!< excluded_RE && ereg(string: cgi_name, pattern: excluded_RE, icase: 1))
      continue;
      if (already_known_flaw(port: port, cgi: cgi_name, vul: vul)) continue;

      if (vul == "SC")
        if (! reload_cookie_jars()) break;

      r = http_send_recv3(method: 'GET', item: cgi_name, port:port);
      if (isnull(r))
      {
        errmsg = http_error_msg();
        if ( !isnull(errmsg) ) set_kb_item(name: 'torture_CGI/error_msg/'+port+'/'+vul, value: errmsg);
        if (++ cnx_errors > max_cnx_errors)
        {
          debug_print('Too many failures (', cnx_errors, ') - CGI = ', cgi_name, ' (', errmsg, ')\n');
          break;
        }
        else
	{
          debug_print('Server did not answer - CGI = ', cgi_name, ' (', errmsg, ')\n');
	  continue;
	}
      }
      if (r[0] !~  "^HTTP/1\..* (200|302) ") continue;

      e = test1url(url: cgi_name, vul: vul);
      if (timed_out) break;
      if (e > 0 && stop_at_first_flaw == "port") break;
      if (e == 0)
      {
        errmsg = http_error_msg();
        if (http_transient_error())
	{
          debug_print('Server did not answer - CGI = ', cgi_name, ' (', errmsg, ')\n');
	  continue;
	}
	else
	{
          if ( ! isnull(errmsg) ) set_kb_item(name: 'torture_CGI/error_msg/'+port+'/'+vul, value: errmsg);
        if (++ cnx_errors > max_cnx_errors)
        {
  	  debug_print("Too many failures (", cnx_errors, ") - CGI = ", cgi_name, "\n");
          break;
        }
        else
          debug_print("Server did not answer - skipping CGI = ", cgi_name, "\n");
	}
     }
   }
  }

  cgi_l = get_cgi_list(port: port);
  foreach cgi_name (cgi_l)
  {
    if (timed_out) break;
    # if (cgi_name =~ ".*/$") continue;	
    if (already_known_flaw(port: port, cgi: cgi_name, vul: vul)) continue;

    args_l = get_cgi_arg_list(port: port, cgi: cgi_name);

    # NB: Settings/HTTP/test_arg_values is not used as this would create a huge
    # number of combinations for probably no real gain. This script basically
    # works in "single" mode

    vrequest = strcat(cgi_name,"?");
    n = 0;
    foreach arg (args_l)
    {
      d = get_cgi_arg_val_list(port: port, cgi: cgi_name, arg: arg, fill: 1);
      if (max_index(d) == 0)
        r = "";
      else
      {
        r = d[0];
      }
      arg = replace_cgi_1arg_token(port: port, arg: arg);
      if (n > 0)
        vrequest = strcat(vrequest, '&', arg, '=', r);
      else
        vrequest = strcat(vrequest, arg, '=', r);
      n ++;
    }

    if (vul == "SC")
      if (! reload_cookie_jars()) break;
    http_reauthenticate_if_needed(port: port);

    r = http_send_recv3(method: 'GET', item: my_encode(vrequest), port:port);
    if (isnull(r))
    {
      errmsg = http_error_msg();
      if ( ! isnull(errmsg) ) set_kb_item(name: 'torture_CGI/error_msg/'+port+'/'+vul, value: errmsg);
      if (++ cnx_errors > max_cnx_errors)
      {
        debug_print('Too many failures (', cnx_errors, ') - CGI = ', cgi_name, ' (', errmsg, ')\n');
	break;
      }
      else
      {
        debug_print('Server did not answer - skipping CGI = ', cgi_name, ' (', errmsg, ')\n');
        continue; 
      }
    }
    if (r[0] !~  "^HTTP/1\..* (200|302) ") continue;

    e = test1url(url: vrequest, vul: vul);
    if (timed_out) break;
    if (e > 0 && stop_at_first_flaw == "port") break;
    if (e == 0)
    {
      errmsg = http_error_msg();
      if (http_transient_error())
        debug_print('Server did not answer - CGI = ', cgi_name, ' (', errmsg, ')\n');
      else
      {
        if ( ! isnull(errmsg) ) set_kb_item(name: 'torture_CGI/error_msg/'+port+'/'+vul, value: errmsg);
      if (++ cnx_errors > max_cnx_errors)
      {
        debug_print("Too many failures (", cnx_errors, ") - CGI = ", cgi_name, "\n");
        break;
      }
      else
          debug_print("Server did not answer - skipping CGI = ", cgi_name, "\n");
      }
    }
  }

  if (cnx_errors > 0)
    set_kb_item(name: "torture_CGI/errors/"+port+"/"+vul, value: cnx_errors);

  report = torture_cgi_build_report(port: port, url_h: success, vul: vul, full_req: 1);
  if (strlen(report) > 0)
  {
    # security_hole(port:port, extra: txt);
    if (vul == "SC" || vul == "SH")
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    if (vul == "XH")
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }

  if (timed_out)
    if (strlen(report) == 0)
      set_kb_item(name: "torture_CGI/timeout/"+port, value: vul);
    else
      set_kb_item(name: "torture_CGI/unfinished/"+port, value: vul);
  else
    set_kb_item( name: "torture_CGI/duration/"+port+"/SB", 
    		 value: unixtime() - start_time);

  debug_print(url_count, " URL were tested on port ", port);
  return report;
}

