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
# torture_cgi_func.inc
# $Revision: 1.79 $
# $Date: 2016/01/08 18:12:14 $
#
include("torture_cgi_sql_inj_msg.inc");
include("torture_cgi_xpath_msg.inc");
include("torture_cgi_err_msg.inc");
include("torture_cgi_pers_XSS_RE.inc");

global_var	try_all_meth, test_arg_val, stop_at_first_flaw;
global_var	webapptests_timeout, try_hpp;
global_var	max_tested_values, abort_time, start_time;
global_var	postheaders, url_count, req_count, excluded_RE;
global_var	success, reports, requests, _flaw_cnt, fp_count;
global_var	thorough_tests, owasp10;
global_var	_cgi_param;




####

function replace_unprintable_char()
{
  local_var	s;

  s = _FCT_ANON_ARGS[0];
  s = str_replace(string: s, find: '\0', replace: '%00');
  s = str_replace(string: s, find: '\r', replace: '%0D');
  s = str_replace(string: s, find: '\n', replace: '%0A');
  return s;
}


global_var	kb_global_nb, kb_cgi_nb;
kb_global_nb = 0;	# per port actually, as we always call get_kb_item
	       		# which "forks".
kb_cgi_nb = make_array();

function torture_cgi_remember(port, cgi, param, method, url, response, response2, vul, report, postdata, request, request2, anti_fp, dont_report)
{
  local_var	k, k2, i, r, c, saturated_kb;


  if (isnull(vul) || isnull(port) || isnull(cgi) || isnull(url))
    err_print("torture_cgi_remember: missing argument port=", port, " vul=", vul, " cgi=", cgi, " url=", url);
  else
  {
    if (cgi[0] != '/') cgi = strcat('/', cgi);
    if (isnull(kb_cgi_nb[cgi])) kb_cgi_nb[cgi] = 1; else kb_cgi_nb[cgi] ++;
  }
  kb_global_nb ++;
  saturated_kb = (kb_global_nb > 20 && kb_cgi_nb[cgi] > 1);

  c = ""; if (saturated_kb) c = " - too many data in KB already.";

  url = replace_unprintable_char(url);
  if (! isnull(postdata)) postdata = replace_unprintable_char(postdata);

  if (isnull(postdata))	k = url;
  else			k = strcat(url, ' [', postdata,']');

  debug_print(level:2, "torture_cgi_remember(port=", port, ", cgi=", cgi, ", param=", param, ", method=", method, ", url=", url, ", vul=", vul, ", anti_fp=", anti_fp, ", dont_report=", dont_report, ", postdata=", postdata, ", request=", request, ", request2=", request2, c);

#  if (method == "G") method = "GET";
#  else if (method == "P") method = "POST";

  if (isnull(request) && ! saturated_kb) request = http_last_sent_request();

  if (anti_fp)
  {
    set_kb_item(name: 'www/'+port+'cgi-FP'+cgi, value: TRUE);

    if (saturated_kb) return NULL;
    set_kb_blob( name: strcat("wwwFP/", port, "/cgi_", vul, "/request/", fp_count),
    		 value: request );
    if (! isnull(request2))
    set_kb_blob( name: strcat("wwwFP/", port, "/cgi_", vul, "/request2/", fp_count),
    		 value: request2 );
    if (isnull(param))
      debug_print('torture_cgi_remember: param is NULL\n');
    else
       set_kb_item( name: strcat("wwwFP/", port, "/cgi_", vul, "/param/", fp_count), value: param );
    if (isnull(response))
      debug_print("torture_cgi_remember: response is NULL\n");
    else
    {
      r = strcat(response[0], response[1], '\r\n', response[2]);
      set_kb_blob( name: strcat("wwwFP/", port, "/cgi_", vul, "/response/", fp_count), value: r);
    }
    if (isnull(response2))
      debug_print("torture_cgi_remember: response2 is NULL\n");
    else
    {
      r = strcat(response2[0], response2[1], '\r\n', response2[2]);
      set_kb_blob( name: strcat("wwwFP/", port, "/cgi_", vul, "/response2/", fp_count), value: r);
    }
    return fp_count ++;
  }

  if (! dont_report)
  {
    if (! report)
    {
      debug_print(level:2, ">> torture_cgi_remember(port=", port, ", cgi=", cgi, ", method=", method, ", url=", url, ' : report is void!\n');
      report = beginning_of_response(resp: response[2]);
    }
    else
      set_kb_blob( name : strcat("www/", port, "/cgi_", vul, "/report/", _flaw_cnt),
    	         value: report );
    # Avoid report truncation in GUI
    if ('\0' >< report) report = str_replace(string: report, find: '\0', replace: '.');

    k2 = strcat(method, "$", k);
    if (isnull(reports[k2]))
    {
      success[method] = strcat(success[method], k, '\n');
    }
    else
    {
      debug_print("torture_cgi_remember: ", method, " ", k, " is already registered\n");
      for (i = 2; TRUE; i ++)
      {
        k2 = strcat(method, '$', k, ' {', i, '}');
        if (isnull(reports[k2])) break;
      }
      success[method] = strcat(success[method], k, ' {', i, '}\n');
    }
    if (! isnull(cgi) && ! isnull(param))
      _cgi_param[k2] = strcat(cgi, '\t', param);
    reports[k2] = report;
    requests[k2] = request;

    # torture_cgi_potential_DOM_XSS.nasl is prone to FPs.
    if (vul[0] == "X" && vul != "XD")
    {
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      set_kb_item(name: "/tmp/XSS/"+port+cgi, value: TRUE);
    }
    if (vul[0] == "Q")
      set_kb_item(name: 'www/'+port+'/XSRF', value: TRUE);
    # Note that S2 is more a weakness than a real flaw
    if (vul[0] == "S" && (report_paranoia > 1 || vul != "S2"))
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    set_kb_item(name: "/tmp/"+vul+"/"+port+cgi, value: TRUE);
    set_kb_item(name: "/tmp/"+vul+"/"+port, value: TRUE);
  }

  if (! saturated_kb)
  {
    set_kb_blob( name: "www/"+port+"/cgi_"+vul+"/request/" + _flaw_cnt,
    		 value: request );
    if (! isnull(request2))
      set_kb_blob( name: "www/"+port+"/cgi_"+vul+"/request2/" + _flaw_cnt,
    		 value: request2 );
    if (isnull(param))
      debug_print('torture_cgi_remember: param is NULL\n');
    else
       set_kb_item( name: strcat("www/", port, "/cgi_", vul, "/param/", _flaw_cnt), value: param );
    if (isnull(response))
      debug_print("torture_cgi_remember: response is NULL\n");
    else
    {
      r = strcat(response[0], response[1], '\r\n', response[2]);
      set_kb_blob( name: strcat("www/", port, "/cgi_", vul, "/response/", _flaw_cnt), value: r );
    }
    if (isnull(response2))
      debug_print("torture_cgi_remember: response2 is NULL\n");
    else
    {
      r = strcat(response2[0], response2[1], '\r\n', response2[2]);
      set_kb_blob( name: strcat("www/", port, "/cgi_", vul, "/response2/", _flaw_cnt), value: r);
    }
  }	# ! saturated_kb
  return _flaw_cnt ++;
}


function torture_cgi_build_report(port, url_h, vul, full_req)
{
  local_var	m, r, report, rep1, rep2, z, u, k, v, prev;

  foreach m (make_list("GET", "POST"))
  {
    rep1 = '';
    r = url_h[m];
    if (strlen(r) > 0)
    {
      rep1 = strcat(rep1, '+ The following resources may be vulnerable to ', torture_cgi_name(code: vul), ' :\n\n');
      foreach u (split(r, keep: 0))
      {
	k = strcat(m, '$', u);
	if (_cgi_param[k] && _cgi_param[k] != prev)
	{
	  prev = _cgi_param[k];
	  v = split(_cgi_param[k], sep:'\t', keep:0);
	  rep1 = strcat(rep1, '+ The \'', v[1], '\' parameter of the ', v[0], ' CGI :\n\n');
	}
        rep1 = strcat(rep1, split_long_line(line: u), '\n');
	if (full_req)
	  rep1 = strcat(rep1, '\n-------- request --------\n', 
	       chomp(requests[k]),
	        '\n------------------------\n');
	if (report_verbosity >= 1 && ! isnull(reports))
	  rep1 = strcat(rep1, '\n-------- output --------\n',
	       chomp(reports[k]),
	       '\n------------------------\n\n');

      }

      if (m == "GET")
      {
        rep2 = '';
        foreach u (split(r, keep: 0))
        {
	  if (strlen(u) < 72 && u !~ " {[0-9]+}$")
	  {
	    z = build_url(port: port, qs: chomp(u));
	    if (strlen(z) < 80)
	      rep2 = strcat(rep2, z, '\n');
	  }
        }


	if (rep2)
          rep1 = strcat(rep1, 'Clicking directly on these URLs should exhibit the issue :\n(you will probably need to read the HTML source)\n\n', rep2, '\n');
      }

      if (strlen(rep1) > 0)
      {
        report = strcat(report, '\nUsing the ', m, ' HTTP method, Nessus found that :\n\n', rep1);
      }
    }
  }
  return report;
}


_dyn_pat_RE = make_list(
# Debug code
  '^[ \t]*Page rendered in[ \t]*:[ \t].*[0-9.]+.*s|Page g&eacute;n&eacute;r&eacute;e en [0-9.]+ secondes? '
# Seen on Tomcat
, '^[ \t]*Memory Used:[ \t]*[0-9]+MB[ \t]*$'
);
function dynamic_web_content(l1, l2)
{
  local_var	p;

  foreach p (_dyn_pat_RE)
    if (ereg(string: l1, pattern: p) && ereg(string: l2, pattern: p))
      return 1;
  return 0;
}

ANSWER_SAME	 = 0;
ANSWER_DIFF_CODE = 1;
ANSWER_DIFF_HTML = 2;

function cmp_html(h1, h2)
{
  local_var	lines1, lines2, i, n, l1, l2, n2, n1;

  if (h1 == h2) return ANSWER_SAME;

  lines1 = split(h1, keep: 0);
  lines2 = split(h2, keep: 0);
  n1 = max_index(lines1);
  n2 = max_index(lines2);
  n = n1; if (n2 > n) n = n2;

  for (i = 0; i < n; i ++)
  {
    l1 = ''; l2 = '';
    if (i < n1) l1 = lines1[i]; 
    if (i < n2) l2 = lines2[i];
    if (l1 != l2)
    {
      if (dynamic_web_content(l1: l1, l2: l2)) continue;
      #### Remove default/checked options ####
      l1 = ereg_replace(string: l1, pattern: '<(input|option)( | .* )(selected="selected"|checked="checked")', icase: 1, replace: "\1\2");
      l2 = ereg_replace(string: l2, pattern: '<(input|option)( | .* )(selected="selected"|checked="checked")', icase: 1, replace: "\1\2");
      ########################################
      if (l1 == l2) continue;
      return i + ANSWER_DIFF_HTML;
    }
  }
  return ANSWER_SAME;
}

function answers_differ(r1, r2)
{
  local_var	c1, c2, h1, h2;

  if (isnull(r1))
    if (isnull(r2))
      return ANSWER_SAME;
    else
      return ANSWER_DIFF_CODE;
   else
     if (isnull(r2))
       return ANSWER_DIFF_CODE;

  if (typeof(r1) != 'array' || typeof(r2) != 'array')
  {
    err_print('answers_differ: r1=', typeof(r1), ' r2=', typeof(r2));
    return NULL;
  }
  c1 = int(substr(r1[0], 9));
  c2 = int(substr(r2[0], 9));
  if (c1 != c2) return ANSWER_DIFF_CODE;

  h1 = sanitize_utf16(body: r1[2], headers: r1[1]);
  h2 = sanitize_utf16(body: r2[2], headers: r2[1]);
  return cmp_html(h1: h1, h2: h2);
}

function utf16_to_ascii(s)
{
  local_var	z, txt;
  # See http://www.w3.org/TR/html4/charset.html#h-5.2.1.1
  txt = str_replace(string: s, find: '\0', replace: '');
  z = substr(txt, 0, 1);
  if (z == '\xFF\xFE' || z == '\xFE\xFF')
    txt = substr(txt, 2);
  return txt;
}

function sanitize_utf16(headers, body)
{
 if (egrep(string: headers, pattern: '^Content-Type:.*charset=UTF-16', icase: 1))
   return utf16_to_ascii(s: body);
 else
  return body;
}

function compute_diff(r1, r2, idx)
{
  local_var	i, j, r, lines, txt, len, maxlen;

  maxlen = 4 * 72;

  if (idx <= 0)
  {
    err_print("compute_diff: invalid idx=", idx);
    idx = answers_differ(r1:r1, r2:r2);
    if (idx <= 0) return NULL;
  }
  if (idx == 1)
  {
    r = strcat(chomp(r1[0]), '\n-------- vs --------\n', chomp(r2[0]), '\n');
    return r;
  }

  idx -= ANSWER_DIFF_HTML; r = "";

  for (j = 0; j < 2; j ++)
  {
    # charset may be UTF-16LE or UTF-16
    if (j == 0)
      txt = sanitize_utf16(body:r1[2], headers: r1[1]);
    else
      txt = sanitize_utf16(body:r2[2], headers: r2[1]);

    lines = split(txt, keep: 0);
    for (i = idx - 2; i <= idx + 2; i ++)
    {
      if (i >= 0)
      {
        len = strlen(lines[i]);
        if (len > 72)
	{
	  if (i == idx)
	  {
	    if (len > maxlen)
	    {
              r = strcat(r, split_long_line(line: 
	      	substr(lines[i], 0, maxlen - 1 - 6) + ' [...]'), '\n');
	    }
	    else
              r = strcat(r, split_long_line(line: lines[i]), '\n');
	  }
	  else
            r = strcat(r, substr(lines[i], 0, 65), ' [...]\n');
	}
        else
          r = strcat(r, lines[i], '\n');
      }
    }
    if (j == 0)
      r = strcat(r, '-------- vs --------\n');
  }
  return r;
}


function already_known_flaw(port, cgi, vul)
{
  local_var	k;

  if (stop_at_first_flaw == "never" || stop_at_first_flaw == "param") return 0;

  if (cgi[0] != '/') cgi = strcat('/', cgi);
  if (get_kb_item("/tmp/"+vul+"/"+port+cgi))
    return 1;

  if (stop_at_first_flaw == "port" &&
      get_kb_item("/tmp/"+vul+"/"+port)) return 1;

  if (thorough_tests) return 0;

  # XSS & persistent XSS
  if (vul[0] == "X")
  {
      if ( get_kb_item("/tmp/XSS/"+port+cgi) || 
           get_kb_item("/tmp/XS/"+port+cgi) ||
	   get_kb_item("/tmp/XH/"+port+cgi) ||
           get_kb_item("/tmp/X2/"+port+cgi) ||
           get_kb_item("/tmp/X3/"+port+cgi) ||
           get_kb_item("/tmp/XI/"+port+cgi) ||
	   get_kb_item("/tmp/XP/"+port+cgi) )
        return 1;
      if (stop_at_first_flaw == "port" && get_kb_item('www/'+port+'/XSS'))
          return 1;

    return 0;
  }

  # Visible SQL injections  
  # As blind SQL injections are more prone to FPs and cannot be demonstrated
  # easily, let's privilege the visible SQL injections.
  if (vul =~ "^S[IHC2N]")
  {
    foreach k (make_list("SI", "SH", "SN", "SC"))
    {
      if ( stop_at_first_flaw == "port" &&
           get_kb_item("/tmp/"+k+"/"+port) )
        return 1;

      if (get_kb_item("/tmp/"+k+"/"+port+cgi))
        return 1;
    }
    return 0;
  }

  # Blind SQL injections
  if (vul[0] == "S")
  {
    if ( stop_at_first_flaw == "port" &&
         get_kb_item('www/'+port+'/SQLInjection') )
      return 1;

    if ( get_kb_item("/tmp/SI/"+port+cgi) ||
       	 get_kb_item("/tmp/SB/"+port+cgi) ||
      	 get_kb_item("/tmp/ST/"+port+cgi) ||
       	 get_kb_item("/tmp/SH/"+port+cgi) ||
	 get_kb_item("/tmp/SN/"+port+cgi) ||
	 get_kb_item("/tmp/SL/"+port+cgi) ||
	 get_kb_item("/tmp/S4/"+port+cgi) ||
       	 get_kb_item("/tmp/SC/"+port+cgi) )
      return 1;

    return 0;
  }

  # Local file inclusion: remote file inclusion or directory traversal are worse
  if (vul == "WL")
  {
    foreach k (make_list("WR", "TD", "TW", "TQ", "T2"))
    {
      if (get_kb_item("/tmp/"+k+"/"+port+cgi)) return 1;
      if (stop_at_first_flaw == "port" && get_kb_item("/tmp/"+k+"/"+port))
        return 1;
    }
  }

  # Directory traversal: write access is worse than read access but testing
  # read access twice is useless
  if (vul == "TD" || vul == "TQ" || vul == "T2")
  {
    foreach k (make_list("TW", "TD", "TQ", "T2"))
    {
      if (get_kb_item("/tmp/"+k+"/"+port+cgi)) return 1;
      if (stop_at_first_flaw == "port" && get_kb_item("/tmp/"+k+"/"+port))
        return 1;
    }
  }

  # Command execution is worse than code injection & do not test cmd exec twice
  if (vul == "EC" || vul == "ET" || vul == "EX")
  {
    foreach k (make_list("EX", "ET"))
    {
      if (get_kb_item("/tmp/"+k+"/"+port+cgi)) return 1;
      if (stop_at_first_flaw == "port" && get_kb_item("/tmp/"+k+"/"+port))
        return 1;
    }
  }

  return 0;
}


function shrink_list(l, n)
{
  local_var	v, i;

  if (max_index(l) <= n) return l;
  for (i = 0; i < n; i ++)
    v[i] = l [i];
  return v;
}

# Some attacks are already encoded, other attacks relies on the fact that 
# special characters are not encoded. We have to be careful and do not call
# urlencode()
function my_encode()
{
  local_var	u;

  u = _FCT_ANON_ARGS[0];
  u = str_replace(string: u, find: ' ',  replace: "%20");
  u = str_replace(string: u, find: '\t', replace: "%09");
  u = str_replace(string: u, find: '\n', replace: "%0A");
  u = str_replace(string: u, find: '\r', replace: "%0D");
  # u = str_replace(string: u, find: '\0', replace: "%00");
  return u;
}

function strridx()
{
  local_var	s, c, i, len;

  s = _FCT_ANON_ARGS[0]; c = _FCT_ANON_ARGS[1];
  len = strlen(s);
  for (i = len -1 ; i >= 0; i --)
    if (s[i] == c)
      return i;
  return -1;
}

# No warning if the argument is void
function mk_list_silent()
{
  if (isnull(_FCT_ANON_ARGS[0]))
   return make_list();
  else
   return make_list(_FCT_ANON_ARGS[0]);
}

function mk_list_silent3()
{
  if (isnull(_FCT_ANON_ARGS[2]))
   return make_list(_FCT_ANON_ARGS[0], _FCT_ANON_ARGS[1]);
  else
   return make_list(_FCT_ANON_ARGS[0], _FCT_ANON_ARGS[1], _FCT_ANON_ARGS[2]);
}

#

INJECTABLE_HTML = 2;
INJECTABLE_TEXT = 1;
INJECTABLE_NO   = 0;

function get_cgi_list(port, injectable_only)
{
  local_var	cgi_l;

  if (injectable_only == INJECTABLE_HTML)
    cgi_l = get_kb_list(strcat("www/", port, "/html_injection/cgi"));
  else if (injectable_only == INJECTABLE_TEXT)
    cgi_l = get_kb_list(strcat("www/", port, "/injectable/cgi"));
  else
    cgi_l = get_kb_list(strcat("www/", port, "/cgi"));

  return mk_list_silent(cgi_l);
}

#
# See also get_cgi_arg_list() and get_cgi_arg_val_list()
# torture_cgi.inc contains an example of code.
#
function get_cgi_arg_list(port, cgi, injectable_only)
{
  local_var	args_l;

  if (injectable_only == INJECTABLE_HTML)
    args_l = get_kb_list(strcat("www/", port, "/html_injection/cgi-arg", cgi));
  if (injectable_only == INJECTABLE_TEXT)
    args_l = get_kb_list(strcat("www/", port, "/injectable/cgi-arg", cgi));
  else
    args_l = get_kb_list(strcat("www/", port, "/cgi-arg", cgi));
  return mk_list_silent(args_l);
}

#
# This function must be called on the output of get_cgi_arg_list()
# *after* get_cgi_arg_val_list() has been used.
# See torture_cgi.inc for an example.
#
function replace_cgi_args_token(port, args_list, max_tokens)
{
  local_var	l, a, t, tkl, sz, i;

  if (isnull(max_tokens))
  {
    err_print("replace_cgi_args_token: missing arg max_tokens");
    return args_list;
  }

  max_tokens = int(max_tokens);
  if (max_tokens <= 0)
  {
    l = make_list("");
    tkl["128"] = l;
    tkl["160"] = l;
    tkl["256"] = l;
  }
  else
  {
    foreach sz (make_list("128", "160", "256"))
    {
      l = get_kb_list("www/"+port+"/token"+sz);
      if (isnull(l))
        tkl[sz] = make_list("");
      else
        tkl[sz] = shrink_list(l: l, n: max_tokens);
    }
  }

  l = make_list(); i = 0;
  # We should probably use only tokens of the right size...
  foreach a (args_list)
    if ("BITS$" >!< a)
      l[i++] = a;
    else
    {
      foreach sz (make_list("128", "160", "256"))
        if ("$"+sz+"BITS\$" >< a)
	{
          foreach t (tkl[sz])
	    l[i ++] = str_replace(string: a, find: "$"+sz+"BITS$", replace: t);
	  break;
	}
    }
  return l;
}

function replace_cgi_1arg_token(port, arg)
{
  local_var	v, tk, tkl, len;

  v = eregmatch(string: arg, pattern: "^(.*)\$([0-9]+)BITS\$(.*)$");
  if (isnull(v)) return arg;

  len = int(v[2]);
  tkl = get_kb_list("www/"+port+"/token"+len);
  if (isnull(tkl))
     tk = "";
  else
    tk = tkl[0];
  tkl = NULL;
  return strcat(v[1], tk, v[3]);
}


function get_form_action_list(port, cgi)
{
  local_var	l;

  l = get_kb_list(strcat("www/", port, "/form-action", cgi));
  return mk_list_silent(l);
}

# The form "method" attribute is case insensitive. webmirror.nasl converts
# it to lower case.
function get_form_method_list(port, cgi)
{
  local_var	l;

  l = get_kb_list(strcat("www/", port, "/form-method", cgi));
  if (! isnull(l))
  {
    l = make_list(l);
    if (max_index(l) > 0) return l;
  }
  return make_list("get");					# Default
}

#
# This function returns a hash
#
function get_cgi_methods(port, cgi)
{
  local_var	l, v, h;

  l = get_form_method_list(port: port, cgi: cgi);
  h = make_array();
  foreach v (make_list(l))
    h[tolower(v)] = 1;
  return h;
}

# The form "enctype" attribute is case insensitive. webmirror.nasl converts
# it to lower case.
function get_form_enctype_list(port, cgi)
{
  local_var	l;

  l = get_kb_list(strcat("www/", port, "/form-enctype", cgi));
  if (! isnull(l))
  {
    l = make_list(l);
    if (max_index(l) > 0) return l;
  }
  return make_list("application/x-www-form-urlencoded");	# Default
}

global_var	_cgi_any_arg_val;

#
# This function must be called on the result of get_cgi_arg_list()
# *before* it is modified by replace_cgi_args_token()
# See torture_cgi.inc
#
function get_cgi_arg_val_list(port, cgi, arg, fill, vuln)
{
  local_var	l;
  local_var     i, n;

  l = get_kb_list(strcat("www/", port, '/cgi-params', cgi, "/", arg));
  l = mk_list_silent(l);
  n = max_index(l);
  for ( i = 0 ; i < n ; i ++ ) l[i] = urlencode(str:l[i]);
  if (fill)
    if (max_index(l) == 0 || max_index(l) == 1 && l[0] == '')
    {
      # If we're testing Blind SQLi on an input field without a value, seed the empty value with rand()
      # since it will be valid for a string or int field when injecting into context of a query. 
      # Otherwise, use rand_str() to seed the empty values for attacks where this doesn't matter.
      if (isnull(_cgi_any_arg_val) && vuln != "SB" ) _cgi_any_arg_val = rand_str();
      else _cgi_any_arg_val = (rand() % 999999);
      l = make_list('', _cgi_any_arg_val);
    }
  return l;
}

#

function build_url_data(port, method, item, data)
{
  if (isnull(data))
    return build_url(port: port, qs: item);
  if (method == "GET")
  {
    if ("?" >< item)	item = strcat(item, '&', data);
    else		item = strcat(item, '?', data);
    return build_url(port: port, qs: item);
  }
  return build_url(port: port, qs: item) + ' [ ' + data + ' ]';
}

function http_send_get_post(port, method, item, data, post_headers, only_content, follow_redirect, fetch404, exit_on_fail)
{
  local_var	u, w;

  method = toupper(method);
  if (method == "GET")
  {
    if (! isnull(data))
    {
      if ("?" >< item)	item = strcat(item, '&', data);
      else		item = strcat(item, '?', data);
    }
    data = NULL;
  }
  if (method == "GET") post_headers = NULL;
  w = http_send_recv3(port: port, method: method, item: item, data: data, add_headers: post_headers, only_content: only_content, follow_redirect: follow_redirect, fetch404: fetch404, exit_on_fail: exit_on_fail);
  if (isnull(w))
  {
    if (method == "GET")
      debug_print(method, ' ', build_url(port: port, qs: item), 'failed\n');
    else
      debug_print(method, ' ', build_url(port: port, qs: item), ' [ ', data, ' ] failed\n');
  }
  return w;
}

#

function torture_cgi_init(vul)
{
  local_var	m, embedded, port;

  webapptests_timeout = int(get_kb_item("Settings/HTTP/max_run_time"));
  if (webapptests_timeout <= 0) exit(0, 'Web application tests are disabled');

  owasp10 = get_kb_item("Settings/HTTP/OWASP10");
  start_time = unixtime();
  abort_time = start_time + webapptests_timeout;
  url_count = 0; req_count = 0;
  _flaw_cnt = 0; fp_count = 0; 
  postheaders = make_array("Content-Type", "application/x-www-form-urlencoded");

  try_all_meth = get_kb_item("Settings/HTTP/try_all_http_methods");
  test_arg_val = get_kb_item("Settings/HTTP/test_arg_values");

  embedded = get_kb_item("Settings/HTTP/test_embedded");
  if ( ! embedded ) embedded = get_kb_item("Settings/PCI_DSS");
  port = get_http_port(default: 80, embedded: embedded);

  if (get_kb_item("www/"+port+"/no_web_app_tests"))
    exit(0, "Web app tests are disabled on port " + port+".");

  if (! isnull(vul))
  {
    m = get_kb_item('www/'+port+'/will_timeout/'+vul);
    if (strlen(m) > 0)
      test_arg_val = m;
  }

  if (match(string: test_arg_val, pattern: "some_*"))
  {
    max_tested_values = get_kb_item("Settings/HTTP/max_tested_values");
    if (max_tested_values <= 0) max_tested_values = 3;
  }
  else
    max_tested_values = 0;
  stop_at_first_flaw = get_kb_item("Settings/HTTP/stop_at_first_flaw");

  excluded_RE = get_kb_item("Settings/HTTP/excluded_items_regex");
  try_hpp = get_kb_item("Settings/HTTP/http_parameter_pollution");
  if (! isnull(vul))
  {
    set_kb_item(name: '/tmp/launched/'+vul+'/'+port, value: TRUE);
    if (vul[0] == 'X')
      set_kb_item(name: '/tmp/launched/XSS/'+port, value: TRUE);
    if (vul =~ '^S[^2]$')
      set_kb_item(name: '/tmp/launched/SQLi/'+port, value: TRUE);
  }
  http_set_async_sock(1);	# Better error handling
  return port;
}

# Check if PHP files are interpreted and not returned as source

function broken_www_interpretor(port, ext_l, pattern, vul)
{
  local_var	e, u, n, n_ko, w, l, s;

  n = 0; n_ko = 0;
  foreach e (ext_l)
  {
    l = get_kb_list(strcat("www/", port, "/content/extensions/", e));
    if (isnull(l)) continue;
    foreach u (make_list(l))
    {
      w = http_send_recv3(port: port, item: u, method: "GET", exit_on_fail: 0);
      if (isnull(w)) break;
      n ++;
      s = extract_pattern_from_resp(response: w, pattern: pattern, dont_clean: 1);
      if (strlen(s) > 0)
      {
        torture_cgi_remember(port: port, cgi: u, method: "GET", url: u, response: w, vul: vul, anti_fp: 1, dont_report: 1);
	n_ko ++;
	if (n_ko >= 3) return 1;
      }
    }
  }
  if (n == 0) return NULL;
  if (n >= 3) return 0;
  if (n_ko > 0) return 1;
  return 0;
}

function broken_php_interpretor(port, vul)
{
  return broken_www_interpretor(port: port, vul: vul, 
    ext_l: make_list("php", "php3", "php4", "php5"), pattern: 'RE:<\\?php');
}

function broken_asp_interpretor(port, vul)
{
  return broken_www_interpretor(port: port, vul: vul, 
    ext_l: make_list("asp", "aspx"), pattern: 'RE:<%@ +LANGUAGE=.* %>');
}

#### Check response for nasty errors and remember it if needed

global_var	fragile_cgi_params, fragile_cgi_nb;
global_var	error_cgi_params, error_cgi_nb;
# We keep only an attack per parameter. Otherwise, we may saturate the memory.
global_var	sqli_cgi_params, xss_cgi_params, xpath_cgi_params;

global_var	_look_for_SQLi, _look_for_XSS;

function torture_cgi_audit_response(port, cgi, url, poisoned_param, request, response, vul, postdata)
{
  local_var	k, code, p, rep, sanresp, lcresp;

  if (isnull(response)) return;
  if (isnull(poisoned_param))
  {
    err_print("torture_cgi_audit_response: missing poisoned_param - port=", port, " cgi=", cgi, "vul=", vul);
    return;
  }
  k = strcat(cgi, '\n', poisoned_param);
  sanresp = NULL;

  if (isnull(_look_for_SQLi))
    _look_for_SQLi = owasp10 || thorough_tests || report_paranoia >= 2 ||
         	   get_kb_item('/tmp/launched/SQLi/'+port);

  # Look for SQL injections - this is expensive
  if (_look_for_SQLi)
  {
    # Already known?
    if (isnull(sqli_cgi_params)) sqli_cgi_params = make_array();
    if (! sqli_cgi_params[k] && 
      ! already_known_flaw(port: port, cgi: cgi, vul: "SI"))
    {
      sanresp = sanitize_utf16(body: response[2], headers: response[1]);
      foreach p (sql_error_patterns)
      {
        rep = extract_pattern_from_resp(string: sanresp, pattern: p);
        if (! isnull(rep))
        {
          debug_print(level:2, "torture_cgi_audit_response: found a SQL injection for vul=", vul, " port=", port, " cgi=", cgi, " url=", url);
          torture_cgi_remember(port: port, cgi: cgi, param: poisoned_param, url: url, response: response, vul: vul, postdata: postdata, request: request, dont_report: 1);
	  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	  # This will be reported by torture_cgi_sql_injection2.nasl
	  # SI is more paranoid than S2...
	  set_kb_item(name: "/tmp/SI/"+port+cgi, value: TRUE);
    	  set_kb_item(name: "/tmp/SI/"+port, value: TRUE);
	  sqli_cgi_params[k] = 1;
	  break;
	}
      }
    }

    # Already known?
    if (isnull(xpath_cgi_params)) xpath_cgi_params = make_array();
    if (! xpath_cgi_params[k] && 
      ! already_known_flaw(port: port, cgi: cgi, vul: "BI"))
    {
      if (isnull(sanresp))
        sanresp = sanitize_utf16(body: response[2], headers: response[1]);
      foreach p (xpath_error_patterns)
      {
        rep = extract_pattern_from_resp(string: sanresp, pattern: p);
        if (! isnull(rep))
        {
          debug_print(level:2, "torture_cgi_audit_response: found an XPath injection for vul=", vul, " port=", port, " cgi=", cgi, " url=", url);
          torture_cgi_remember(port: port, cgi: cgi, param: poisoned_param, url: url, response: response, vul: vul, postdata: postdata, request: request, dont_report: 1);
	  set_kb_item(name: 'www/'+port+'/XPathInjection', value: TRUE);
	  set_kb_item(name: "/tmp/BI/"+port+cgi, value: TRUE);
    	  set_kb_item(name: "/tmp/BI/"+port, value: TRUE);
	  xpath_cgi_params[k] = 1;
	  break;
	}
      }
    }
  }

  # Look for persistent XSS too
  if ( vul != "XP" &&
       # thorough_tests &&
       get_kb_item("/tmp/launched/XP/"+port+cgi) && # Poison has been sent
       ! already_known_flaw(port: port, cgi: cgi, vul: "XP") )
  {
    # Already known?
    if (isnull(xss_cgi_params)) xss_cgi_params = make_array();
    if (! xss_cgi_params[k])
    {
      if (isnull(sanresp))
        sanresp = sanitize_utf16(body: response[2], headers: response[1]);
       foreach p (pers_xss_regex)
       {
         rep = egrep(string: sanresp, pattern: p, icase: 1);
         if (! isnull(rep))
         {
           debug_print(level:2, "torture_cgi_audit_response: found a permanent XSS for vul=", vul, " port=", port, " cgi=", cgi, " url=", url);
           torture_cgi_remember(port: port, cgi: cgi, url: url, response: response, vul: vul, postdata: postdata, request: request, dont_report: 1);
	   # This will be reported by torture_cgi_persistent_XSS2.nasl
	   # set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	   # set_kb_item(name: "/tmp/XP/"+port+cgi, value: TRUE);
	   # set_kb_item(name: "/tmp/XP/"+port, value: TRUE);
	   xss_cgi_params[k] = 1;
	   break;
	 }
      }
    }
  }

  if (isnull(_look_for_XSS))
  {
    if (vul[0] == 'X')
      _look_for_XSS = 0;
    else
      _look_for_SQLi = owasp10 || thorough_tests || 
    		     get_kb_item('/tmp/launched/XP/'+port);
  }

  if (_look_for_XSS && ! already_known_flaw(port: port, cgi: cgi, vul: "XP"))
  {
    if (isnull(xss_cgi_params)) xss_cgi_params = make_array();
    if (! xss_cgi_params[k])
    {
      if (isnull(sanresp))
        sanresp = sanitize_utf16(body: response[2], headers: response[1]);
      foreach p (refl_xss_patterns)
      {
        rep = egrep(string: sanresp, pattern: p, icase: 1);
        if (! isnull(rep))
        {
          debug_print(level:2, "torture_cgi_audit_response: found a permanent XSS for vul=", vul, " port=", port, " cgi=", cgi, " url=", url);
          torture_cgi_remember(port: port, cgi: cgi, url: url, response: response, vul: vul, postdata: postdata, request: request, dont_report: 1);
	  # This will be reported by torture_cgi_persistent_XSS3.nasl
 	  xss_cgi_params[k] = 1;
	  break;
        }
      }
    }
  }

  # The other tests only make sense in OWASP Top 10 mode
  if (! owasp10) return;

  # Look for 500 errors
  if (response[0] =~ "^HTTP/1\.[01] +50[0-9]")
  {
    # Already known?
    if (isnull(fragile_cgi_params)) fragile_cgi_params = make_array();
    if (! fragile_cgi_params[k])
    {
      fragile_cgi_params[k] = 1;

      if (isnull(fragile_cgi_nb)) fragile_cgi_nb = 0;

      i = stridx(response[0], '5');
      code = substr(response[0], i, i + 2);

      set_kb_item(name: "www/"+port+"/code/"+code+"/cgi", value: cgi);
      set_kb_item(name: "www/"+port+"/code/"+code+"/cgi-arg"+cgi, value: poisoned_param);

      if (isnull(request)) request = http_last_sent_request();
      set_kb_blob( name: "www/"+port+"/code/"+code+"/cgi_"+vul+"/request/"+fragile_cgi_nb, value: request );
      set_kb_blob( name: "www/"+port+"/code/"+code+"/cgi_"+vul+"/response/"+fragile_cgi_nb, value: strcat(response[0], response[1], '\r\n', response[2]) );
      fragile_cgi_nb ++;
      return;
    }
  }

  # Look for common errors
  lcresp = tolower(sanresp);
  if ("erro" >< lcresp || "warning" >< lcresp || "exception" >< lcresp)	# Optimize
  {
    foreach p (err_msg_patterns)
    {
      rep = extract_pattern_from_resp(string: sanresp, pattern: p);
      if (! isnull(rep))
      {
        # Already known?
	if (isnull(error_cgi_params)) error_cgi_params = make_array();
	if (! error_cgi_params[k])
	{
      	  error_cgi_params[k] = 1;
	  if (isnull(error_cgi_nb)) error_cgi_nb = 0;

	  set_kb_item(name: "www/"+port+"/error/cgi", value: cgi);
	  set_kb_item(name: "www/"+port+"/error/cgi-arg"+cgi, value: poisoned_param);
	  if (isnull(request)) request = http_last_sent_request();
	  set_kb_blob( name: "www/"+port+"/error/cgi_"+vul+"/request/"+error_cgi_nb, value: request );
	  set_kb_blob( name: "www/"+port+"/error/cgi_"+vul+"/response/"+error_cgi_nb, value: strcat(response[0], response[1], '\r\n', response[2]) );
    	  error_cgi_nb ++;
          break;
	}
      }
    }
  }
}

function extract_sql_backend_from_kb(port, count_only)
{
  local_var	resp_l, item, k, k2, db, v, code, idx, nb, txt, req, resp, lines, p;

  resp_l = get_kb_list("www/"+port+"/cgi_*/response*/*");
  db = make_array();
  foreach k (keys(resp_l))
  {
    v = eregmatch(string: k, pattern: "/cgi_([A-Z][A-Z])/response([0-9]*)/([0-9]+)");
    if (isnull(v)) continue;
    code = v[1]; idx = v[2]; nb = v[3];
    k2 = str_replace(string: k, find: "/response"+idx+"/", replace: "/request"+idx+"/");

    resp = decode_kb_blob(value:resp_l[k]);

    # Ignore Tomcat /appdev/processes*.html and /docs/.*.html files
    req = get_kb_item(k2);
    req = decode_kb_blob(value: req);

    if (ereg(
      pattern : "(/appdev/.*\.html|/docs/.*\.html)",
      string  : req,
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

    foreach p (sql_error_patterns)
    {
      txt = extract_pattern_from_resp(string: resp, pattern: p, dont_clean: 1);
      if (! isnull(txt)) break;      
    }
    if (strlen(txt) > 0)
    {
      req = get_kb_list(k2);
      item = '';
      if (! isnull(req))
      {
        req = decode_kb_blob(value: req[0], name: k2);
        lines = split(req, keep: 0);
        v = eregmatch(string: lines[0], pattern: "^[A-Z]+ +(/[^ ]*) +HTTP/1\.[01]$");
        if (! isnull(v)) item = v[1];
      }

      if (egrep(string: txt, pattern: "(ORA|PLS)-[0-9]{5}[^0-9]") || "PL/SQL" >< txt)
        if (count_only)
	  db["Oracle"] ++;
	else
          db["Oracle"] = strcat(item, '\n', db["Oracle"]);

      if (" PostgreSQL " >< txt || "PostgreSQL query failed:" >< txt)
        if (count_only)
	  db["PostgreSQL"] ++;
	else
	  db["PostgreSQL"] = strcat(item, '\n', db["PostgreSQL"]);

      if ("Microsoft SQL Native Client" >< txt || 
          "ODBC SQL Server Driver" >< txt ||
	  ("Syntax error converting the " >< txt && " to a column of data type " >< txt) ||
	  "Incorrect syntax near " >< txt ||
	  (" expects parameter " >< txt && "which was not supplied" >< txt) ||
	  "All queries in an SQL statement containing a UNION operator must have an equal number of expressions in their target lists" >< txt ||
	    "Unclosed quotation mark before the character string " >< txt ||
	  egrep(string: txt, pattern: "Msg [0-9]+, Level [0-9]+, State [0-9]+, Line [0-9]+") ||
          "[SQL Server" >< txt)
	if (count_only)
	  db["MS SQL Server"] ++;
	else
	  db["MS SQL Server"] = strcat(item, '\n', db["MS SQL Server"]);

      if ("Microsoft][Driver ODBC Microsoft Access]" >< txt)
        if (count_only)
	  db["MS Access"] ++;
	else
	  db["MS Access"] = strcat(item, '\n', db["MS Access"]);

      if (" MySQL " >< txt || "mysql_query()" >< txt || 
          "mySQL error with query" >< txt ||
	  "The used SELECT statements have a different number of columns" >< txt ||
          "mysql_connect()" >< txt)
	if (count_only)
	  db["MySQL"] ++;
	else
	  db["MySQL"] = strcat(item, '\n', db["MySQL"]);

      if ("[IBM][CLI Driver][DB2/6000]" >< txt)
        if (count_only)
	  db["IBM DB2"] ++;
	else
	  db["IBM DB2"] = strcat(item, '\n', db["IBM DB2"]);
    }
  }
  return db;
}


function torture_cgi_untestable_param(cgi, param)
{
  if (cgi =~ "\.aspx$")
  {
    # ASP.NET special argument
    if (ereg(string: param, icase: 1, pattern: "^__(SCROLLPOSITION[XY]|VIEWSTATE(ENCRYPTED|GENERATOR|FIELDCOUNT|[1-9])?|LASTFOCUS|PREVIOUSPAGE|EVENT(VALIDATION|ARGUMENT|TARGET))"))
      return 1;
  }
  if (cgi =~ "\.php$")
  {
    if (ereg(string: param, icase: 1, pattern: "^Qform__FormState"))
	return 1;
  }
  if (cgi =~ "\.jsp$")
  {
    if (ereg(string: param, icase: 1, pattern: "^com\.sun\.faces\.VIEW"))
	return 1;
  }
  return 0;
}
