#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(33817);
 script_version ("$Revision: 1.63 $");
 
 script_name(english: "CGI Generic Tests Load Estimation (all tests)");
 
 script_set_attribute(attribute:"synopsis", value:
"Load estimation for web application tests." );
 script_set_attribute(attribute:"description", value:
"This script computes the maximum number of requests that would be done 
by the generic web tests, depending on miscellaneous options. 
It does not perform any test by itself.

The results can be used to estimate the duration of these tests, or 
the complexity of additional manual tests.

Note that the script does not try to compute this duration based 
on external factors such as the network and web servers loads.");

 script_set_attribute(attribute:"solution", value: "n/a" );
 script_set_attribute(attribute:"risk_factor", value: "None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2009/10/26");
 script_cvs_date("$Date: 2014/03/12 13:40:30 $");
 script_set_attribute(attribute:"plugin_type", value:"summary");
 script_end_attributes();

 script_summary(english: "Estimate the number of requests done by the web app tests");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("global_settings.nasl", "web_app_test_settings.nasl", "webmirror.nasl", "torture_cgi_load_estimation1.nasl", "torture_cgi_load_estimation2.nasl", "torture_cgi_load_estimation3.nasl");
 script_require_keys("Settings/enable_web_app_tests");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("torture_cgi_load_estimation.inc");
include("url_func.inc");

####

l1 = get_kb_list('www/'+port+'/load_estimation/1meth/*/*');
l2 = get_kb_list('www/'+port+'/load_estimation/2meth/*/*');

if (isnull(l1) && isnull(l2)) exit(0, 'No load estimation data in KB.');

if (test_arg_val == 'single') selected_m = 'S';
else if (test_arg_val == 'some_pairs') selected_m = 'SP';
else if (test_arg_val == 'all_pairs') selected_m = 'AP';
else if (test_arg_val == 'some_combinations') selected_m = 'SC';
else if (test_arg_val == 'all_combinations') selected_m = 'AC';

####

skl = make_list();
tot9 = make_array(); totA9 = make_array();

if (! isnull(l1))
  foreach k (keys(l1))
  {
    v = eregmatch(string: k, pattern: '^www/[0-9]+/load_estimation/1meth/([A-Z0-9]+)/([A-Z]+)$');
    if (isnull(v))
      err_print('Cannot parse ', k, '\n');
    else
    {
      attack = v[1]; mode = v[2];
      tot[mode+':'+attack] = l1[k];
      tot9[mode] = add_overflow(a: tot9[mode], b: l1[k]);
      skl = make_list(skl, attack);
    }
  }

if (! isnull(l2))
  foreach k (keys(l2))
    {
    v = eregmatch(string: k, pattern: '^www/[0-9]+/load_estimation/2meth/([A-Z0-9]+)/([A-Z]+)$');
    if (isnull(v))
      err_print('Cannot parse ', k, '\n');
    else
      {
      attack = v[1]; mode = v[2];
      totA[mode+':'+attack] = l2[k];
      totA9[mode] = add_overflow(a: totA9[mode], b: l2[k]);
      skl = make_list(skl, attack);
      }
    }
#

report1 = ''; report2 = '';
skl = list_uniq(skl);

foreach k (skl)
{
    n = torture_cgi_name(code: k);
    report1 = strcat(report1, n, space(41 - strlen(n)), ':');
    report2 = strcat(report2, n, space(41 - strlen(n)), ':');
    foreach m (modes_l)
    {
      report1 = strcat(report1, ' ', m, '=', tot[m+":"+k], space(11 - strlen(strcat(m, tot[m+":"+k]))));
    report2 = strcat(report2, ' ', m, '=', totA[m+":"+k], space(11 - strlen(m+totA[m+":"+k])));
    }
    report1 += '\n'; report2 += '\n';
}


if (! report1 || ! report2) exit(0, "No CGI were found on port "+port+".");

####

report1 = strcat(report1, '\nAll tests', space(32), ':');
report2 = strcat(report2, '\nAll tests', space(32), ':');
foreach m (modes_l)
{
  report1 = strcat(report1, ' ', m, '=', tot9[m], space(11 - strlen(strcat(m, tot9[m]))));
  report2 = strcat(report2, ' ', m, '=', totA9[m], space(11 - strlen(strcat(m, totA9[m]))));
}
report1 += '\n'; report2 += '\n';

####

l = get_kb_list('www/'+port+'/will_timeout/*');
report3 = '';
if (! isnull(l))
{
  foreach k (keys(l))
  {
    v = eregmatch(string: k, pattern: '^www/[0-9]+/will_timeout/([A-Z0-9]+)$');
    if (isnull(v))
      err_print('Cannot parse ', k);
    else
    {
      n = torture_cgi_name(code: v[1]);
      c_len = 40 - strlen(n);
      if ( c_len <= 0 ) c_len = 1;
      report3 = strcat(report3, n, crap(length: c_len, data: ' '),
        l[k], '\n');
    }
  }
  if (report3)
    report3 = 
'\nThe following tests would have timed out in the selected mode and \n' +
'have been degraded to a quicker mode :\n' + report3 + '\n';
}

####

report = strcat(
"Here are the estimated number of requests in miscellaneous modes
for one method only (GET or POST) :
[Single / Some Pairs / All Pairs / Some Combinations / All Combinations]

",
report1,
"
Here are the estimated number of requests in miscellaneous modes
for both methods (GET and POST) :
[Single / Some Pairs / All Pairs / Some Combinations / All Combinations]

",
report2,
'\nYour mode : ' + test_arg_val + ', ');
if (try_all_meth) report += 'GET and POST';
else report += 'GET or POST';
if (thorough_tests) report += ', thorough tests';
if (experimental_scripts) report += ', experimental tests';
if (!get_kb_item("Settings/PCI_DSS") && report_paranoia > 1) report += ', Paranoid';
report += '.\n';
report += 'Maximum number of requests : ';

if (try_all_meth) report += strcat(totA9[selected_m], '\n');
else 	     report += strcat(tot9[selected_m], '\n');


if (strlen(report3) > 0)
 report += report3;

security_note(port: port, extra: report);
