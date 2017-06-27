#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(42425);
 script_version ("$Revision: 1.39 $");
 script_cvs_date("$Date: 2017/01/05 15:28:31 $");

 script_name(english: "CGI Generic XSS (persistent)");
 script_summary(english: "Tortures the arguments of the remote CGIs (persistent XSS)");

 script_set_attribute(attribute:"synopsis", value:
"A CGI application hosted on the remote web server is potentially
prone to cross-site scripting attack.");
 script_set_attribute(attribute:"description", value:
"The remote web server hosts one or more CGI scripts that fail to
adequately sanitize request strings containing malicious JavaScript. 
By leveraging this issue, an attacker may be able to cause arbitrary
HTML and script code to be executed in a user's browser within the
security context of the affected site. 

These issues are likely to be 'persistent' or 'stored', but this
aspect should be checked manually.  Please note that persistent 
cross-site scripting can be triggered by any channel that provides 
information to the application.  Nessus cannot test them all." );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Cross_site_scripting#Persistent" );
 script_set_attribute(attribute:"see_also", value:"http://projects.webappsec.org/Cross-Site+Scripting");
 script_set_attribute(attribute:"solution", value:
"Restrict access to the vulnerable application or contact the vendor 
for a patch or upgrade." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_cwe_id(
  20,  # Improper Input Validation
  74,  # Improper Neutralization of Special Elements in Output Used by a Downstream Component 'Injection'
  79,  # Cross-Site Scripting
  80,  # Improper Neutralization of Script-Related HTML Tags in a Web Page Basic XSS
  81,  # Improper Neutralization of Script in an Error Message Web Page
  83,  # Improper Neutralization of Script in Attributes in a Web Page
  86,  # Improper Neutralization of Invalid Characters in Identifiers in Web Pages
  116, # Improper Encoding or Escaping of Output
  442, # Web problems
  692, # Incomplete Blacklist to Cross-Site Scripting
  712, # OWASP Top Ten 2007 Category A1 - Cross-Site Scripting XSS
  722, # OWASP Top Ten 2004 Category A1 - Unvalidated Input
  725, # OWASP Top Ten 2004 Category A4 - Cross-Site Scripting XSS Flaws
  751, # 2009 Top 25 - Insecure Interaction Between Components
  801, # 2010 Top 25 - Insecure Interaction Between Components
  811, # OWASP Top Ten 2010 Category A2 - Cross-Site Scripting XSS
  928, # Weaknesses in OWASP Top Ten 2013
  931  # OWASP Top Ten 2013 Category A3 - Cross-Site Scripting XSS
 );
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/06");


 script_set_attribute(attribute:"plugin_type", value:"remote");

 script_end_attributes();

 # Not dangerous, but we want to give it a chance to run after the normal XSS tests
 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses : XSS");
 script_dependencie("http_version.nasl", "webmirror.nasl", "cross_site_scripting.nasl", "web_app_test_settings.nasl", "torture_cgi_load_estimation1.nasl");
 script_require_ports("Services/www", 80);
 script_timeout(43200);	# Timeout is managed by the script itself
 script_require_keys("Settings/enable_web_app_tests");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("torture_cgi_func.inc");
include("url_func.inc");

####

i = 0;
poison[i++] = "<script>alert($URL$);</script>";
poison[i++] = "<BODY ONLOAD=alert($URL$)>";
poison[i++] = "<<<<<<<<<<$URL$>>>>>";
poison[i++] = ">>>>>>>>>>$URL$<<<<<";
# To be completed...

# Regular expressions are in torture_cgi_pers_XSS_RE.inc


####

port = torture_cgi_init(vul:'XP');

if (get_kb_item(strcat("www/", port, "/generic_xss"))) exit(1, "The web server itself is prone to XSS attacks.");
if (! thorough_tests && stop_at_first_flaw == "port" && get_kb_item(strcat("www/", port, "/XSS"))) exit(0);

################################

seen_req = make_array();

global_var	success, reports, flaw_cnt, seen_req, visible_on;

function remember(port, method, req, req2, report, response)
{
  local_var	k;
  local_var	rq, buf, idx;

  debug_print(level:2, "remember: port=", port, " method=", method, " req=", req, " req2=", req2, "\n");

  if (method == "G") method = "GET";
  if (method == "P") method = "POST";
  
  k = strcat(method, "$", req);
  if (seen_req[k]) return;
  seen_req[k] = 1;

  success[method] = strcat(success[method], req, '\n');
  visible_on[k] = req2;
  reports[k] = report;

  # rebuild the initial request
  if (method == "GET")
    rq = http_mk_get_req(port: port, item: req);
  else
  {
    idx = stridx(req, "?");
    if (idx > 0)
    {
      rq = http_mk_post_req(port: port, item: substr(req, 0, idx - 1), data: substr(req, idx+1));
    }
  }
  if (! isnull(rq))
  {
    buf = http_mk_buffer_from_req(req: rq);
    set_kb_blob( name: strcat("www/", port, "/cgi_XP/request/", flaw_cnt),
    		 value: buf );
  }

  set_kb_blob( name: strcat("www/", port, "/cgi_XP/request2/", flaw_cnt),
  	       value: http_last_sent_request() );
  set_kb_blob( name: strcat("www/", port, "/cgi_XP/response/", flaw_cnt),
  	       value: strcat(response[0], response[1], '\r\n', response[2]) );

  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);

  flaw_cnt ++;
}

function extract_regex_from_resp(string, regex)
{
  local_var	lines, i, n, i1, i2, rep, v;

  lines = split(string);
  n = max_index(lines);
  for (i = 0; i < n; i ++)
  {
    v = eregmatch(string: lines[i], pattern: regex, icase: 1);
    if (! isnull(v))  break;
  }
  if (isnull(v)) return NULL;
  rep = "";
  i1 = i - 2; i2 = i + 2;	# Change this if you want more or less context
  if (i1 < 0) i1 = 0;
  if (i2 >= n) i2 = n - 1;
  for (i = i1; i <= i2; i ++)
    rep = strcat(rep, clean_string(s: lines[i]), '\n');
  return make_list(v[1], v[2], rep);
}

global_var	timed_out, postheaders, pattern, excluded_RE;

global_var	pers_xss_regex;

function test(port, url, cgi, meth, postdata, poisoned_param)
{
  local_var r, k, rep, dir, act, v, retry, ct, cnt;

  if (get_kb_item("Settings/PCI_DSS") || report_paranoia < 2)
    ct = "text/(xml|html)";
  else
    ct = NULL;

  debug_print(level:3, meth, ' URL=', url, ' - port=', port, ' - postdata=', postdata, '\n');
  url = my_encode(url);
  if (excluded_RE && ereg(string: url, pattern: excluded_RE, icase: 1))
    return -1;

  dir = NULL;
  if (isnull(postdata))
    act = make_list(url);
  else
  {
    # Cleanly encoding the posted data is not necessary so far
    # postdata = urlencode(str: postdata, case: HEX_UPPERCASE);
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
    if (excluded_RE && ereg(string: url, pattern: excluded_RE, icase: 1))
      continue;

    # The web app tests are very long, this increases the risk of network glitch 
    for (retry = 1; retry <= 3; retry ++)
    {
      if (isnull(postdata))
        r = http_send_recv3(port:port, method: meth, item: url,                                           follow_redirect: 4, only_content: ct);
      else
        r = http_send_recv3(port:port, method: meth, item: url, data: postdata, add_headers: postheaders, follow_redirect: 4, only_content: ct);
      if (! isnull(r)) break;
    }
    if (isnull(r))
    {
      debug_print('http_send_recv3=NULL\n');
      return 0;
    }
    if (! isnull(poisoned_param))
      torture_cgi_audit_response(port: port, cgi: cgi, url: url, vul: "XP", poisoned_param: poisoned_param, postdata: postdata, response: r);
    if (r[0] =~ "^HTTP/1\.[01] 400 ")
      debug_print(level:2, 'test(', url, ') = ', r[0]);

    for (i = 0; pattern[i]; i ++)
    {
      rep = extract_regex_from_resp(regex: pers_xss_regex[i], string:r[2]);
      if (! isnull(rep))
      {
        remember(port: port, method: rep[0], req: hex2raw(s: rep[1]), response: r, req2: url, report: rep[2]);
	# ?
	if (stop_at_first_flaw != "never" && stop_at_first_flaw != "param")
	  return 1;
	cnt ++; break;
      }
    }
  }
  if (cnt > 0)
    return 1;
  else
    return -1;
}

global_var	url_count;

function test1url(port, url, poisoned_param)
{
  local_var	e, url16, u, meth_h;
  local_var	idx, cgi, mypostdata;


  if (unixtime() > abort_time)
  {
    debug_print('Timeout! Aborted!\n');
    timed_out ++;
    return 0;
  }
  url_count ++;

  url16 = hexstr(url);
  u = str_replace(string: url, find: "$URL$", replace: "G"+url16);
  idx = stridx(url, '?');
  if (idx < 0) cgi = url;
  else cgi = substr(url, 0, idx - 1);

  if (! try_all_meth) meth_h =  get_cgi_methods(port: port, cgi: cgi);
  if (try_all_meth || meth_h["get"])
    {
  e = test(port:port, meth: "GET", url: u, cgi: cgi, poisoned_param: poisoned_param);
  if (e >= 0) return e;
  }

  if (try_all_meth || meth_h["post"])
    {
    u = str_replace(string: url, find: "$URL$", replace: "P"+url16);
      e = test(port: port, meth: 'POST', url: cgi, cgi: cgi, postdata:mypostdata, poisoned_param: poisoned_param);
      return e;
    }
  return -1;
}

global_var	poison, test_arg_val;

function test_cgi_rec(port, url, param_l, data_ll, idx, poison_idx, var_idx)
{
  local_var	i, j, d, u, e, fl, val, head, cnt;

  #display("test_cgi_rec: port=", port, " url=", url, " idx=", idx, " poison_idx=", poison_idx, " var_idx=", var_idx,"\n");

  if (isnull(param_l[idx]))	# last argument
    return test1url(port: port, url: url, poisoned_param: param_l[poison_idx]);

  d = data_ll[idx];
  if ((test_arg_val == "all_pairs"|| test_arg_val == "some_pairs") && var_idx > 0)
    d = make_list(d[0]);

  cnt = 0;
  if (idx == poison_idx)
  {
    foreach fl (poison)
     for (i = 0; ! isnull(d[i]); i ++)
     {
       if (idx > 0) u = strcat(url, "&"); else u = url;
       if ("VALUE"  >< fl)
       {
         if (max_index(d) > 0) val = d[0];
	 else val = "foobar";
         u = strcat(u, param_l[idx], '=', 
	   str_replace(string: fl, find:"VALUE", replace:val));
       }
       else
         u = strcat(u, param_l[idx], '=', fl);

       e = test_cgi_rec(port:port, url: u, param_l: param_l, data_ll: data_ll, idx: idx + 1, poison_idx: poison_idx, var_idx: var_idx);
       cnt ++;
       if (e >= 0)
         if (stop_at_first_flaw == "param")
	   break;
	 else if (stop_at_first_flaw != "never")
	   return e;
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
      e = test_cgi_rec(port:port, url: u, param_l: param_l, data_ll: data_ll, idx: idx + 1, poison_idx: poison_idx, var_idx: var_idx);
       cnt ++;
       if (e >= 0)
         if (stop_at_first_flaw == "param")
	   break;
	 else if (stop_at_first_flaw != "never")
	   return e;
    }
  if (cnt > 0)
    return 1;
  else
    return -1;
}


global_var	stop_at_first_flaw;

function test1cgi(port, cgi, param_l, data_ll)
{
  local_var	i, e, cnt;

  cnt = 0;
  for (i = 0; ! isnull(param_l[i]); i ++)
  {
    if (already_known_flaw(port: port, cgi: cgi, vul: "XP"))
    {
      debug_print(level:2, "test1cgi port=",port, " cgi=", cgi, " vul=XP -- flaw has already been reported");
      return -1;
    }

    set_kb_item(name: "/tmp/launched/XP/"+port+cgi, value: TRUE);
 
    init_cookiejar();
    e = test_cgi_rec(port:port, url: strcat(cgi, "?"), param_l: param_l, data_ll: data_ll, idx: 0, poison_idx: i, var_idx: -1);
    cnt ++;
    if (! e) return 0;
    if (e > 0 && stop_at_first_flaw != "never" && stop_at_first_flaw != "param") return e;
  }
  if (cnt > 0)
    return 1;
  else
    return -1;
}

####

flaw_cnt = 0;

########
 
global_var	test_arg_val, success, reports, timed_out, stop_at_first_flaw, visible_on;

function torture_cgis(port)
{
  local_var	cgis, cgi_name, r, num_args, args_l, arg, d, vals_l, e, k;
  local_var	rep1, rep2, vulns, report, m, u, cnx_errors;
  local_var	url_l, prev_url, z;
  local_var     kb;

  if (get_kb_item("www/"+port+"/no_web_app_tests"))
  {
    debug_print("torture_cgis: web app tests are disabled on port ", port);
    return NULL;
  }
  cgis = get_cgi_list(port: port);
  if (max_index(cgis) == 0) return NULL;
  timed_out = 0;

  success = make_array();
  reports = make_array();
  visible_on = make_array();
  cnx_errors = 0;

  cgis = make_list(cgis);
  foreach cgi_name (cgis)
  {
    # No need to report several XSS
    if (already_known_flaw(port: port, cgi: cgi_name, vul: "XP")) continue;

    args_l = get_cgi_arg_list(port: port, cgi: cgi_name);
    num_args = 0;
    foreach arg (args_l)
    {
      d = get_cgi_arg_val_list(port: port, cgi: cgi_name, arg: arg, fill: 1);
      if (test_arg_val == "single") d = make_list(d[0]);
      if (max_tested_values > 0) d = shrink_list(l: d, n: max_tested_values);
      vals_l[num_args ++] = d;
    }
    args_l = replace_cgi_args_token(port: port, args_list: args_l, max_tokens: 1);
   e = test1cgi(port:port, cgi: cgi_name, param_l: args_l, data_ll: vals_l);
   if (! e)
    if (++ cnx_errors > 32)
     break;
    else
     debug_print("Server did not answer. Switching to new CGI\n");

   if (e > 0)
     set_kb_item(name: "/tmp/XSS/"+port+cgi_name, value: TRUE);
   if (e > 0 && stop_at_first_flaw == "port") break;
  }

  # look again at the web site
  if (url_count > 0 && (flaw_cnt == 0 || thorough_tests))
  {
    debug_print(level:2, "Last check...\n");
    kb = get_kb_list("www/"+port+"/content/extensions/*"); 
    if ( !isnull(kb) ) 
     url_l = sort(make_list(kb));
    else
     url_l = NULL;

    prev_url = NULL;
    foreach u (url_l)
      if (u != prev_url)
      {
        prev_url = u;
        e = test1url(port: port, url: u);
        if (! e && ++ cnx_errors > 3) break;
      }
   }

  if (cnx_errors > 0)
    set_kb_item(name: "torture_CGI/errors/"+port+"/XP", value: cnx_errors);

  report = '';

  foreach m (make_list("GET", "POST"))
  {
    r = success[m];
    if (strlen(r) > 0)
    {
      rep1 = strcat(rep1, '+ The following resources may be vulnerable to cross-site scripting :\n\n');
      if (report_verbosity < 1)
      {
        rep1 = strcat(rep1, r, '\n');
      }
      else
      {
        foreach u (split(r, keep: 0))
	{
	  k = strcat(m, '$', u);
          rep1 = strcat(rep1, split_long_line(line: u), '\nSeen on :\n', split_long_line(line: visible_on[k]), '\n-------- output --------\n', reports[k], '------------------------\n\n');
	}
        rep1 = strcat(rep1, '\n');
      }

      if (m == "GET")
      {
        rep2 = "";
        foreach u (split(r, keep: 0))
        {
	  if (strlen(u) < 72)
	  {
	    z = build_url(port: port, qs: chomp(u));
	    if (strlen(z) < 80)
	      rep2 = strcat(rep2, build_url(port: port, qs: chomp(u)), '\n');
	  }
        }
	if (strlen(rep2) > 0)
        rep1 = strcat(rep1, 'Clicking directly on these URLs might expose the vulnerabilities :\n(you will probably need to check the HTML source)\n\n', rep2, '\n');
      }

      if (strlen(rep1) > 0)
      {
        report = strcat(report, '\nUsing the ', m, ' HTTP method, Nessus found that :\n\n', rep1);
      }
    }
  }
  if (timed_out)
    if (!report)  set_kb_item(name: "torture_CGI/timeout/"+port, value: "XP");
    else set_kb_item(name: "torture_CGI/unfinished/"+port, value: "XP");
  else
    set_kb_item(name:"torture_CGI/duration/"+port+"/XP", value: unixtime() - start_time);

  debug_print(level: 2, url_count, ' URL were tested on port ', port, ' (args=', test_arg_val, ')');
  return report;
}

rep = torture_cgis(port: port);
if (rep)
{
  security_warning(port: port, extra: rep);
}

