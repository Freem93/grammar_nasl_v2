#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(39471);
 script_version ("$Revision: 1.10 $");
 
 script_name(english: "Web Application Tests Settings");
 
 script_set_attribute(attribute:"synopsis", value:
"HTTP audit options." );
 script_set_attribute(attribute:"description", value:
"This script sets options for generic web tests. It does not perform 
any test by itself.

Several scripts use the options set here to test web applications,
look for cross-site scripting attacks, SQL injection, etc. in CGIs.");

 script_set_attribute(attribute:"solution", value:
"n/a" );
 script_set_attribute(attribute:"risk_factor", value:
"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2009/06/19");
 script_cvs_date("$Date: 2011/09/21 18:57:16 $");
 script_set_attribute(attribute:"plugin_type", value:"settings");
 script_end_attributes();

 script_summary(english: "HTTP attacks settings");
 script_category(ACT_SETTINGS);
 script_copyright(english: "This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");
 script_family(english: "Settings");
 script_add_preference(name: "Enable web applications tests", type: "checkbox", value: "no");
 # script_add_preference(name: "Extended OWASP Top 10 coverage (for manual review)", type: "checkbox", value: "no");
 script_add_preference(name: "Maximum run time (min) : ", type:"entry", value:"60");
 script_add_preference(name: "Try all HTTP methods", type:"checkbox", value:"no");
 script_add_preference(name: "Combinations of arguments values", type:"radio", value:"one value;some pairs;all pairs (slower but efficient);some combinations;all combinations (extremely slow)");
 script_add_preference(name: "HTTP Parameter Pollution", type: "checkbox", value: "no");
 script_add_preference(name: "Stop at first flaw", type:"radio", value:"per CGI;per port (quicker);per parameter (slow);look for all flaws (slower)");
 script_add_preference(name: "Test embedded web servers", type: "checkbox", value: "no");

# This URL must contain a PHP source that displays "NessusCodeExecTest" when
# executed and contains "NessusRemoteFileInclusionTest"
# See http://rfi.nessus.org/rfi.txt
 script_add_preference(name:"URL for Remote File Inclusion : ", type:"entry", value:"http://rfi.nessus.org/rfi.txt");


 script_dependencie("ping_host.nasl", "global_settings.nasl");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

opt = script_get_preference("Enable web applications tests");
if ("yes" >!< opt)
{
  t = 0;
#  set_kb_item(name: "Settings/disable_web_app_tests", value: TRUE);
}
else
{
 set_kb_item(name: "Settings/enable_web_app_tests", value: TRUE);
 t = script_get_preference("Maximum run time (min) : ");
 t = int(t);
 if (t <= 0) t = 60;
 t *= 60;	# seconds
}
set_kb_item(name: "Settings/HTTP/max_run_time", value: t);

opt = script_get_preference("Extended OWASP Top 10 coverage (for manual review)");
if ("yes" >< opt)
  set_kb_item(name: "Settings/HTTP/OWASP10", value: TRUE);

opt = script_get_preference("Try all HTTP methods");
if ("yes" >< opt)
  set_kb_item(name: "Settings/HTTP/try_all_http_methods", value: TRUE);

opt = script_get_preference("Combinations of arguments values");
if ("one value" >< opt)
  set_kb_item(name: "Settings/HTTP/test_arg_values", value: "single");
else if ("all pairs" >< opt)
  set_kb_item(name: "Settings/HTTP/test_arg_values", value: "all_pairs");
else if ("all combinations" >< opt)
  set_kb_item(name: "Settings/HTTP/test_arg_values", value: "all_combinations");
else if ("some pairs" >< opt)
  set_kb_item(name: "Settings/HTTP/test_arg_values", value: "some_pairs");
else if ("some combinations" >< opt)
  set_kb_item(name: "Settings/HTTP/test_arg_values", value: "some_combinations");
else
  set_kb_item(name: "Settings/HTTP/test_arg_values", value: "single");


opt = script_get_preference("HTTP Parameter Pollution");
if ("yes" >< opt)
  set_kb_item(name: "Settings/HTTP/http_parameter_pollution", value: TRUE);

opt = script_get_preference("Stop at first flaw");
if ("per CGI" >< opt)
  set_kb_item(name: "Settings/HTTP/stop_at_first_flaw", value: "CGI");
else if ("per port" >< opt)
  set_kb_item(name: "Settings/HTTP/stop_at_first_flaw", value: "port");
else if ("per parameter" >< opt)
  set_kb_item(name: "Settings/HTTP/stop_at_first_flaw", value: "param");
else if ("look for all flaws" >< opt)
  set_kb_item(name: "Settings/HTTP/stop_at_first_flaw", value: "never");
else
  set_kb_item(name: "Settings/HTTP/stop_at_first_flaw", value: "CGI");

opt = get_preference("web_app_tests.tested_values_for_each_parameter");
n = int(opt);
if (n <= 0) n = 3;	# default value
set_kb_item(name: "Settings/HTTP/max_tested_values", value: n);

opt = script_get_preference("Test embedded web servers");
if ("yes" >< opt)
  set_kb_item(name: "Settings/HTTP/test_embedded", value: TRUE);

opt = script_get_preference("URL for Remote File Inclusion : ");
if (strlen(opt) > 0)
  set_kb_item(name: "Settings/HTTP/remote_file_inclusion_URL", value: opt);
