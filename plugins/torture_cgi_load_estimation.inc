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
# torture_cgi_load_estimation.inc
# $Revision: 2.1 $
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("torture_cgi_func.inc");
include("torture_cgi_names.inc");


########


global_var	timeout, end_mult, nb_attacks;
global_var	tot, totA, modes_l;

mode2key = make_array(
  'single',		'S',
  'some_pairs',		'SP',
  'all_pairs',		'AP',
  'some_combinations',	'SC',
  'all_combinations',	'AC'
);

key2mode = make_array(
  'S',	'single',
  'SP',	'some_pairs',
  'AP',	'all_pairs',
  'SC',	'some_combinations',
  'AC',	'all_combinations'
);

function space()
{
 local_var len;
 len = _FCT_ANON_ARGS[0];
 if ( len < 0 ) return '';
 return crap(data:' ', length:len);
}

function add_overflow(a, b)
{
 local_var	c;
  if (a == '>2G' || b == '>2G') return '>2G';
  c = a + b;
  if (c < a || c < b) return '>2G';
  return c;
}

function mul_overflow(a, b)
{
 local_var	c;

  if ( a == 0 || b == 0 ) return 0;
  if (a == '>2G' || b == '>2G') return '>2G';
  c = a * b;
  if (c < a || c < b) return '>2G';
  return c;
}

function estimate_load(port, cgis, injectable)
{
  local_var	k, nb, meth_h;
  local_var	i, a, t, aa, tt, j, skl, cgi_name, d, n;
  local_var	num_args, num_vals, num_act, arg, args_l;
  local_var	m, c, req_per_sec, ms_per_req;
  local_var	mode_ok, will_timeout, timeout, ti1, ti2, ti;


  skl = sort(keys(nb_attacks));

  foreach m (modes_l)
    foreach k (make_list(skl))
    {
      tot[m+":"+k] = 0;
      totA[m+":"+k] = 0;
    }

  foreach cgi_name (cgis)
  {
    num_args = 0;
    num_vals = make_list();
    num_act = make_list();

    d = get_form_action_list(port: port, cgi: cgi_name);
    num_act = max_index(d);
    if (num_act == 0) num_act = 1;

    meth_h = get_cgi_methods(port:port, cgi:cgi_name);

    args_l = get_cgi_arg_list(port: port, cgi: cgi_name, injectable_only: injectable);
    foreach arg (args_l)
    {
      d = get_cgi_arg_val_list(port: port, cgi: cgi_name, arg: arg, fill: 1);
      n = max_index(d);
      if (n == 0) n = 1;
      num_vals[num_args] = n;
      num_args ++;
    }

    foreach k (keys(nb_attacks))
    {
      foreach m (modes_l) nb[m] = 0;
      nb['S'] = num_args * nb_attacks[k];

      for (i = 0; i < num_args; i ++)
      {
        a = nb_attacks[k]; t = 1;
        aa = a; tt = t;
        for (j = 0; j < num_args; j ++)
        {
          if (i != j)
	  {
	    n = num_vals[j];
	    a = mul_overflow(a: a, b: n);
	    if (n > 1)
	      t += n - 1;

	    if (n > max_tested_values)
	      n = max_tested_values;

	    aa = mul_overflow(a: aa, b: n);
	    if (n > 1) tt += n - 1;
	  }
      	} 
      	nb["AC"] = add_overflow(a: nb["AC"], b: a);
      	nb["AP"] = add_overflow(a: nb["AP"], b: nb_attacks[k] * t);
      	nb["SC"] = add_overflow(a: nb["SC"], b: aa);
      	nb["SP"] = add_overflow(a: nb["SP"], b: nb_attacks[k] * tt);
      }

      debug_print(level: 2, "CGI=", cgi_name, " - N=", num_args, " - AP=", nb["AP"], " - AC=", nb["AC"], " - SP=", nb["SP"], " - SC=", nb["SC"]);

      foreach m (modes_l)
      {
        if (meth_h["get"])
          tot[m+":"+k] = add_overflow(a: tot[m+":"+k], b: nb[m]);
	if (meth_h["post"])
          tot[m+":"+k] = add_overflow(a: tot[m+":"+k], b: mul_overflow(a: nb[m], b: num_act));

        totA[m+":"+k] = add_overflow(a: totA[m+":"+k], b: nb[m]);
        totA[m+":"+k] = add_overflow(a: totA[m+":"+k], b: mul_overflow(a: nb[m], b: num_act));
      }
    }
  }

  foreach k (keys(nb_attacks))
    if (! isnull(end_mult[k]))
    {
      foreach  m (modes_l)
      {
        tot[m+":"+k] = mul_overflow(a: tot[m+":"+k], b: end_mult[k]);
	totA[m+":"+k] = mul_overflow(a: totA[m+":"+k], b: end_mult[k]);
      }
    }

####

  req_per_sec = int(get_kb_item('www/'+port+'/requests_per_sec'));
  ms_per_req = int(get_kb_item('www/'+port+'/ms_per_request'));

  foreach k (skl)
  {
    mode_ok = NULL; will_timeout = 0;
    foreach m (modes_l)
    {
      timeout = 0;
      if (try_all_meth) t = totA[m+":"+k];
      else t = tot[m+":"+k];

      if (t == '>2G')
        timeout ++;
      else
      {
        ti1 = NULL; ti2 = NULL; ti = NULL;
	# We try to use the more precise data
        if (ms_per_req > 0)
	{
          ti1 = mul_overflow(a: ms_per_req, b: t);
	  if (ti1 !=  '>2G') ti1 /= 1000;
	  ti = ti1;
	  debug_print(level: 3, 'vul=', k, ' mode=', m, ' T1=', ti1, '\n');
        }
	if (req_per_sec > 0)
	{
          ti2 = (t / req_per_sec);
	  if (isnull(ti) || ti == '>2G') ti = ti2;
	  debug_print(level: 3, 'vul=', k, ' mode=', m, ' T2=', ti2, '\n');
        }
	if (ti == '>2G') timeout ++;
	else if (ti >= webapptests_timeout) timeout ++;
	# else no data
      }
      if (timeout && key2mode[m] == test_arg_val)
      {
	will_timeout = 1;
      }
      if (! timeout) mode_ok = m;
    }
    if (will_timeout && ! isnull(mode_ok))
    {
      debug_print(k, ' will timeout on port ', port, '. Degrading to mode ', mode_ok);
      set_kb_item(name: 'www/'+port+'/will_timeout/'+k, value: key2mode[mode_ok]);
    }
  }

}


####

if (! get_kb_item("Settings/enable_web_app_tests"))
 exit(0, "Generic web application tests are disabled.");


modes_l = make_list("S", "SP", "AP", "SC", "AC");

# report1 = ""; report2 = "";
timeout = 0;

port = torture_cgi_init();

max_tested_values = get_kb_item("Settings/HTTP/max_tested_values");
if (max_tested_values <= 0) max_tested_values = 3;
# Set by torture_cgi_init()
#  try_all_meth = get_kb_item("Settings/HTTP/try_all_http_methods");

