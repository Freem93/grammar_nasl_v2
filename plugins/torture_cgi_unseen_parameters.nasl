#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(44134);
 script_version ("$Revision: 1.31 $");

 script_name(english: "CGI Generic Unseen Parameters Discovery");
 script_summary(english: "Try common CGI parameters");

 # It could lead to OWASP A4 in some case - Nessus cannot evaluate the impact

 script_set_attribute(attribute:"synopsis", value:
"A CGI application hosted on the remote web server is potentially
prone to information disclosure or privilege escalation.");
 script_set_attribute(attribute:"description", value:
"By sending requests with additional parameters such as 'admin', 'debug',
or 'test' to CGI scripts hosted on the remote web server, Nessus was
able to generate at least one significantly different response even
though the parameters themselves do not actually appear in responses. 

This behavior suggests that such a parameter, while unseen, are used by the
affected application(s) and may enable an attacker to bypass
authentication, read confidential data (like the source of the
scripts), modify the behavior of the application(s) or conduct
similar attacks to gain privileges. 

Note that this script is experimental and may be prone to false
positives." );
 script_set_attribute(attribute:"see_also", value:"http://projects.webappsec.org/Predictable-Resource-Location");
 script_set_attribute(attribute:"solution", value:
"Inspect the reported CGIs and, if necessary, modify them so that
security is not based on obscurity." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_cwe_id(
#  639,	# Access Control Bypass Through User-Controlled Key
  715,	# OWASP Top Ten 2007 Category A4 - Insecure Direct Object Reference
  723,	# OWASP Top Ten 2004 Category A2 - Broken Access Control
  813	# OWASP Top Ten 2010 Category A4 - Insecure Direct Object References
 );
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/25");
 script_cvs_date("$Date: 2017/01/05 15:28:31 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");

 script_dependencie("http_version.nasl", "webmirror.nasl", "web_app_test_settings.nasl", "torture_cgi_load_estimation1.nasl");
 script_require_ports("Services/www", 80);
 script_timeout(43200);	# Timeout is managed by the script itself
 script_require_keys("Settings/enable_web_app_tests");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("torture_cgi_names.inc");
include("torture_cgi_func.inc");
include("url_func.inc");

global_var	success, reports, posreply, posregex, postheaders;
global_var	port, poison_arg, poison_val;
global_var	anti_fp_arg, fp_count;

# Answer to the good request is the first element, 
# answers to bogus requests come next.

global_var	req_resp_l, req_len_l, excluded_RE;

function test(meth, url, postdata, cgi)
{
  local_var	r1, r2, r3, i, j, n, len, req, act, dir, v, z, rep;
  local_var	a, pat, poison, whatever;
  local_var	fpcgi, u1, u2, p2, flag, retry;


  if (excluded_RE && ereg(string: my_encode(url), pattern: excluded_RE, icase: 1))
    return -1;

  fpcgi = get_kb_item('www/'+port+'cgi-FP'+cgi);

  # This may be very slow but is necessary for some technology like ASP.NET
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

  foreach url (act)
  {
    if (url[0] != "/") url = strcat(dir, url);
    u1 = my_encode(url);
    if (excluded_RE && ereg(string: u1, pattern: excluded_RE, icase: 1))
      continue;
    debug_print(level: 2, "M=", meth, " - U=", url, " - D=", postdata);
    r1 = http_send_get_post(item: u1, port:port, method: meth, data: postdata, post_headers: postheaders);

    if (isnull(r1))
    {
      debug_print('http_send_recv3=NULL port=', port);
      return 0;
    }

    foreach a (poison_arg)
    {
      # Is this parameter already used?
      pat = strcat("^(.+&)?",a, "=");
      if (ereg(string: url, pattern: pat, icase: 1))
        continue;
      if (! isnull(postdata) && ereg(string: postdata, pattern: pat, icase: 1))
        continue;
    
      foreach v (poison_val)
      {
        poison = strcat("&", a, "=", v);
        if (isnull(postdata))
        {
          u2 = my_encode(strcat(url, poison)); p2 = NULL;
          debug_print(level: 2, "M=", meth, " - U=", u2);
        }
        else
	{
	  u2 = url;
	  p2 = strcat(postdata, poison);
	}
        r2  = http_send_get_post(item: u2, port:port, method: meth, 
	      data: p2, post_headers: postheaders);

	# Avoid FP & do not lose time on broken server or paranoid WAF
	if (isnull(r2)  && (report_paranoia < 2 || fpcgi))
	{
	  debug_print('http_send_recv3(port=', port, ' url=', url, ' poison=', poison, ')=NULL port=', port);
          return 0;
	}

	z = answers_differ(r1: r1, r2: r2);
        if (! z) continue;
        req = http_last_sent_request();

	if (a == anti_fp_arg)
	{
	  debug_print('http_send_recv3(port=', port, ' url=', url, ' poison=', poison, ') => FP!\n');
	  torture_cgi_remember(anti_fp: 1, port: port, method: meth, request: req, url: u2, postdata: p2, response2: r1, response: r2, cgi: cgi, param: a, vul: "PH", report: rep);
	  return -2;
	}

	# We do not try an "opposite" request like torture_cgi_yesno.inc
	# because of a higher risk of FN. Some buggy web apps may react 
	# to the mere presence of an argument (e.g. debug) and do not 
	# examine its value (e.g. on/off).

        if (report_paranoia < 2 || fpcgi)
	{
	  flag = 1;
	  for (retry = 1; retry <=6 && flag; retry ++)
	  {
            # Double check
  	    sleep(retry);

	    # Normal request
	    r3 = http_send_get_post(item: u1, port:port, method: meth, data: postdata, post_headers: postheaders);
	    if (answers_differ(r1: r1, r2: r3))
	    {
	      flag = 0; break;	      
	    }

	    sleep(1);

	    # Modified request
	    r3 = http_send_get_post(item: u2, port:port, method: meth, data: postdata, post_headers: p2);
	    if (answers_differ(r1: r2, r2: r3))
	    {
	      flag = 0; break;
	    }
	  }
	}

	if (! flag)
	{
          # Retry initial request to make sure that the page did not change 
          # so that we do not get an FP on a forum, for example.
          r3 = http_send_get_post(item: u1, port:port, method: meth, data: postdata, post_headers: postheaders);
    
          if (answers_differ(r1: r1, r2: r3)) flag = 0;
	}

	if (! flag)
	{
	  debug_print('http_send_recv3(port=', port, ' url=', url, ' poison=', poison, ') => FP!\n');
	  torture_cgi_remember(anti_fp: 1, port: port, method: meth, request: req, url: u1, postdata: postdata, response: r1, response2: r2, cgi: cgi, param: a, vul: "PH");
	  fpcgi = 1;
	  break;
	}

	rep = compute_diff(r1: r1, r2: r2, idx: z);
	torture_cgi_remember(port: port, method: meth, request: req, url: u2, postdata: p2, response2: r1, response: r2, cgi: cgi, param: a, vul: "PH", report: rep);
        return 1;
      }	# poison_val
    } # poison_arg
  } # url
  return -1;
}

global_var	timed_out, url_count;

function test1url(url)
{
  local_var	e, idx, cgi, mypostdata, meth_h;

  if (unixtime() > abort_time)
  {
    debug_print('Timeout! Aborted!\n');
    timed_out ++;
    return 0;
  }
  url_count ++;

  idx = stridx(url, '?');
  if (idx >= 0) cgi = substr(url, 0, idx - 1);
  else cgi = url;
  if (! try_all_meth) meth_h = get_cgi_methods(port:port, cgi:cgi);

  if (try_all_meth || meth_h["get"])
  {
  e = test(meth: "GET", url: url, cgi: cgi);
  if (e >= 0) return e;
  }

  if (try_all_meth || meth_h["post"])
  {
  mypostdata = substr(url, idx + 1);
  e = test(meth: 'POST', url: cgi, postdata:mypostdata, cgi: cgi);
  }
  return e;
}

global_var	test_arg_val;

function test_cgi_rec(url, param_l, data_ll, idx, var_idx)
{
  local_var	i, d, u, e;

  if (isnull(param_l[idx]))
    return test1url(url: url);

  d = data_ll[idx];
  if ( (test_arg_val == "all_pairs" || test_arg_val == "some_pairs") && var_idx > 0)
  {
    d = make_list(d[0]);
  }
  else
    var_idx = idx;

  for (i = 0; ! isnull(d[i]); i ++)
  {
    if (idx > 0)
      u = strcat(url, "&", param_l[idx], '=', d[i]);
    else
      u = strcat(url, param_l[idx], '=', d[i]);
    e = test_cgi_rec(url: u, param_l: param_l, data_ll: data_ll, var_idx: var_idx, idx: idx + 1);
    if (e >= 0) return e;
    if (e == -2) return e;
  }
  return -1;
}

global_var	stop_at_first_flaw;

function test1cgi(cgi, param_l, data_ll)
{
  local_var	d, p, e;

  if (already_known_flaw(port: port, cgi: cgi, vul: "PH"))
  {
    debug_print("test1cgi port=",port, " cgi=", cgi, " vul=PH -- flaw has already been reported");
    return -1;
  }

  init_cookiejar(); http_reauthenticate_if_needed(port: port);

  e = test_cgi_rec(url: strcat(cgi, "?"), param_l: param_l, data_ll: data_ll, var_idx: -1, idx: 0);
  return e;
}

##############

anti_fp_arg = rand_str();

poison_arg = make_list(
	anti_fp_arg,
	"admin",
	"administrator",
	"debug",
	"developer",
	"hide",
	"source",
	"test"
);

poison_val = make_list(
	1,
	"on",
	"true",
	"y",
	"yes"
);

################

port = torture_cgi_init(vul:'PH');

success = make_array();
reports = make_array();

if (get_kb_item("www/"+port+"/no_web_app_tests"))
 exit(0, "Web app tests are disabled on port " + port+".");

cgi_l = get_cgi_list(port: port);
foreach cgibase (cgi_l)
{
  http_reauthenticate_if_needed(port: port);

  vrequest = strcat(cgibase,"?");
  n = 0;
  args_l = get_cgi_arg_list(port: port, cgi: cgibase);
  foreach arg (args_l)
  {
    d = get_cgi_arg_val_list(port: port, cgi: cgibase, arg: arg, fill: 1);
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
  if (isnull(r)) break;
  if (r[0] !~  "^HTTP/1\..* (200|302) ") continue;

  if (! test1cgi(cgi: cgibase, param_l: args_l, data_ll: data)) break;
}

report = torture_cgi_build_report(port: port, url_h: success, vul: "PH");
if (strlen(report) > 0)
{
  security_warning(port:port, extra: report);
}

if (timed_out)
  if (strlen(report) == 0) set_kb_item(name: "torture_CGI/timeout/"+port, value: "PH");
  else set_kb_item(name: "torture_CGI/unfinished/"+port, value: "PH");
else
  set_kb_item(name:"torture_CGI/duration/"+port+"/PH", value: unixtime() - start_time);

debug_print(level:2, url_count, ' URL were tested on port ', port, ' (args=', test_arg_val, ')');
