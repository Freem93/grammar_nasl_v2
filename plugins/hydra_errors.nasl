#TRUSTED 44708779e510e8a1bb7762693f8aa47a26283dcd04caac53438f0dada1017b44a35004580b521b3af4e2f41746b643b60945fb0df266ff342aa9cbf740a6f95cb73a045b9a3f2859c078924e2ed9193b12be0e09921f401cbeccc4f727bdf0a6f13f4c8a4d0df1a089de6308479a8500c87273c2fb3d12c572b3cea4d61e6cf4add654e2e9b8f4e650bc2ce8cd01ad0d4f184d3623e6466e382cf8064210d0d9e491e6591241fdee5e597173f2ccec1be7b172561296b74f7013bed3b41013dddf647700855ad5fe625b3643af03b131b5fae8b5b329644543877ec542bc7828cff1e50a4615e721e814da983bdf361a5e0c502ce1ecb06c95517e6630e89abac2ce72bb9b8ade0e91762bb6c0b54793e40c41e7c1598bcac45cdf5bd378fadf3a8f8472619d423eb30c415669c30d95dcc4ddf7412a5b3b0a4a5ea4e2624abdf362947e7afe3059e70d1a9c499b0989b8b859e0e017fa15ebacbd3029c2f948e63979956f6a789f2c3abf93e19e671762dcc3f8a3cf79e9dd8a0cca16d834e2da7ca7bdc752e223734a46475967dee8dd6b4c958148a0b74212ade02c4fafec0225d997777a6cfd824599972746e1a63cf2c72c07e864daefb7c872b70017bd437dc60c9259ac9d63ad0447263567667962d7f20140f6daa24d60fd4000a32b476995c0bde023d5b3f63514ca18dae4f5de74b83ab80289966fef194e110fe2
#
# (C) Tenable Network Security, Inc.
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);


include("compat.inc");

if(description)
{
 script_id(44915);
 script_version ("1.4");
 script_set_attribute(attribute:"plugin_modification_date", value: "2011/03/20");

 script_name(english: "Hydra Error Summary");
 script_summary(english: "Summarizes errors recorded in KB items");

 script_set_attribute(attribute:"synopsis", value:
"Errors happened during Hydra scan." );
 script_set_attribute(attribute:"description", value:
"This plugin sumarizes any errors that were encountered while running
Hydra. 

If any are reported, results from those plugins may be incomplete." );
 script_set_attribute(attribute:"solution", value:
"Reduce the parallelism in the Hydra options.");
 script_set_attribute(attribute:"risk_factor", value: "None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/02/25");
 script_set_attribute(attribute:"plugin_type", value:"summary");
 script_end_attributes();

 script_category(ACT_END);
 script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");
 script_family(english: "Brute force attacks");
 script_dependencie("hydra_options.nasl");
 script_require_keys("/tmp/hydra/force_run");
 exit(0);
}


####

__gs_opt = get_kb_item("global_settings/report_verbosity");
if (__gs_opt)
{
  if ("Normal" >< __gs_opt) report_verbosity = 1;
  else if ("Quiet" >< __gs_opt) report_verbosity = 0;
  else if ("Verbose" >< __gs_opt) report_verbosity = 2;
}
else report_verbosity = 1;



report = "";
l = get_kb_list("Hydra/errors/*/*");
if (isnull(l)) exit(0, "No Hydra/errors/*/* KB items.");

foreach k (keys(l))
{
  v = split(k, sep: "/", keep: 0);
  svc = v[2]; port = int(v[3]);
  if (isnull(svc) || port == 0)
  {
    #err_print("Could not parse KB key: ", k);
    continue;
  }
  n = l[k];
  report = strcat(report, 'The module ', svc, ' reported ', n, ' errors on port ', port, '\n');  
  if (report_verbosity > 1)
  {
    txt = get_kb_item("Hydra/error_msg/"+svc+"/"+port);
    if (strlen(txt) > 0)
     report = strcat(report, '--------\n', txt, '--------\n');
  }
  report += '\n';
}

if (strlen(report) > 0)
  security_note(port: 0, extra: report);
