#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(56243);
 script_version("$Revision: 2.5 $");
 script_cvs_date("$Date: 2014/03/12 13:40:30 $");
 
 script_name(english:"CGI Generic Tests Load Estimation (quick tests, text injection)");
 script_summary(english:"Estimate the number of requests done by the web app tests");
 
 script_set_attribute(attribute:"synopsis", value:
"Load estimation for web application tests.");
 script_set_attribute(attribute:"description", value:
"This script computes the maximum number of requests that would be
done by the generic web tests, depending on miscellaneous options.  It
does not perform any test by itself. 

It adjusts the mode of each script if it is unable to run in the given
time. 

The results can be used to estimate the duration of these tests, or
the complexity of additional manual tests. 

Note that the script does not try to compute this duration based on
external factors such as the network and web server loads.");

 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/21");
 script_set_attribute(attribute:"plugin_type", value:"summary");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("global_settings.nasl", "web_app_test_settings.nasl", "webmirror.nasl", "torture_cgi_injectable_param.nasl");
 script_require_keys("Settings/enable_web_app_tests");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("torture_cgi_load_estimation.inc");
include("url_func.inc");

#### Quick tests (text injection)

nb_attacks = make_array(
 "JR", 9,	# torture_cgi_redirection.nasl
 "YZ", 5,	# torture_cgi_inject_html.nasl
 "HI", 2,	# torture_cgi_header_injection.nasl
 "X3", 6,	# torture_cgi_cross_site_scripting3.nasl
 "XI", 1,	# torture_cgi_script_injection.nasl
 "QO", 1	# torture_cgi_on_site_request_forgery.nasl
);

end_mult = make_array();

if (!get_kb_item("Settings/PCI_DSS") && report_paranoia > 1)
{
 nb_attacks["X3"] += 1;
}

####

cgis = get_cgi_list(port: port, injectable_only: INJECTABLE_TEXT);
if (max_index(cgis) > 0)
{
  estimate_load(port: port, cgis: cgis, injectable: INJECTABLE_TEXT);
}
else
  exit(0, 'No CGI was found on port '+port+'.');

####

foreach m (modes_l)
{
  foreach k (keys(nb_attacks))
  {
    set_kb_item(name: 'www/'+port+'/load_estimation/1meth/'+k+'/'+m, value: tot[m+':'+k]);
    set_kb_item(name: 'www/'+port+'/load_estimation/2meth/'+k+'/'+m, value: totA[m+':'+k]);
  }
}

