#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(56242);
 script_version("$Revision: 2.5 $");
 script_cvs_date("$Date: 2014/03/12 13:40:30 $");
 
 script_name(english:"CGI Generic Tests Load Estimation (full tests)");
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
 script_copyright(english: "This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("global_settings.nasl", "web_app_test_settings.nasl", "webmirror.nasl");
 script_require_keys("Settings/enable_web_app_tests");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("torture_cgi_load_estimation.inc");
include("url_func.inc");

#### Classic tests

nb_attacks = make_array(
 "EX", 16,	# torture_cgi_command_exec.nasl
 "ET", 6,	# torture_cgi_command_exec2.nasl
# "EI", 5,	# torture_cgi_command_exec3.nasl
# "EC",	3,	# torture_cgi_code_injection.nasl
 "TD", 25,	# torture_cgi_directory_traversal.nasl
 "TW", 2,	# torture_cgi_dir_trav_W.nasl
 "T2", 51,	# torture_cgi_directory_traversal2.nasl
 "X2", 4,	# torture_cgi_cross_site_scripting2.nasl
 "XP", 4,	# torture_cgi_persistent_XSS.nasl
# "XD", 1,	# torture_cgi_potential_DOM_XSS.nasl
# "LD", 1,	# torture_cgi_ldap_injection.nasl
 "SI", 24,	# torture_cgi_sql_injection.nasl
 "SB", 4,	# torture_cgi_blind_sql_injection.nasl
 "S4", 1,	# torture_cgi_blind_sql_injection3.nasl
 "S2", 1,	# torture_cgi_sql_error_msg.nasl
 "PH", 1,	# torture_cgi_unseen_parameters.nasl
 "FS", 2,	# torture_cgi_format_string.nasl
 "II", 3,	# torture_cgi_SSI_injection.nasl
# "IH", 5,	# torture_cgi_SSI_injection_headers.nasl
 "ZI", 1,	# torture_cgi_xml_injection.nasl
 "YY", 2,	# torture_cgi_injectable_param.nasl
 "WL", 1,	# torture_cgi_local_file_inclusion.nasl
 "WR", 1	# torture_cgi_remote_file_inclusion.nasl
);

end_mult = make_array(
# "LD", 2,	# torture_cgi_ldap_injection.nasl
 "PH", 7*5,	# torture_cgi_unseen_parameters.nasl
 "S4", 4,	# torture_cgi_blind_sql_injection3.nasl
 "SB", 3	# torture_cgi_blind_sql_injection.nasl
);

# SC, SH, XH, SN, XN use a different system

if (!get_kb_item("Settings/PCI_DSS") && report_paranoia > 1)
{
 nb_attacks["X2"] += 4;
 nb_attacks["SI"] += 1;
}
if (thorough_tests)
{
 nb_attacks["X2"] += 13;
 nb_attacks["WL"] += 3;
}
if (experimental_scripts)
{
 nb_attacks["SB"] += 6;
# nb_attacks["EI"] += 3;
}
if (experimental_scripts || thorough_tests)
{
 nb_attacks["SI"] += 4;
 nb_attacks["EX"] += 6;
 nb_attacks["TD"] += 4;
}

cgis = get_cgi_list(port: port);
if (max_index(cgis) > 0)
{
  estimate_load(port: port, cgis: cgis);
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
