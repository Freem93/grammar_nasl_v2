#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(19506);
 script_version("$Revision: 1.89 $");
 script_cvs_date("$Date: 2017/05/22 21:39:31 $");

 script_name(english:"Nessus Scan Information");
 script_summary(english:"Displays information about the scan.");

 script_set_attribute(attribute:"synopsis", value:
"This plugin displays information about the Nessus scan.");
 script_set_attribute(attribute:"description", value:
"This plugin displays, for each tested host, information about the
scan itself :

  - The version of the plugin set.
  - The type of scanner (Nessus or Nessus Home).
  - The version of the Nessus Engine.
  - The port scanner(s) used.
  - The port range scanned.
  - Whether credentialed or third-party patch management
    checks are possible.
  - The date of the scan.
  - The duration of the scan.
  - The number of hosts scanned in parallel.
  - The number of checks done in parallel.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/26");

 script_set_attribute(attribute:"plugin_type", value:"summary");
 script_set_attribute(attribute:"agent", value:"all");
 script_end_attributes();

 if ( !isnull(ACT_END2) ) script_category(ACT_END2);
 else script_category(ACT_END);
 script_family(english:"Settings");

 script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");

 exit(0);
}

include('plugin_feed_info.inc');
include('smb_hotfixes.inc');
include('smb_glue.inc');
include('agent.inc');

old_feed_alert = 0;
NESSUS6 = make_list(6,10,5);
nes_ver = NESSUS_VERSION;
nes_level = NASL_LEVEL;
myVersion = NULL;

if (!isnull(nes_ver))
{
  array = split(nes_ver, sep:'.', keep:FALSE);
  myVersion = make_list(int(array[0]), int(array[1]), int(array[2]));

  if ( myVersion[0] < NESSUS6[0] || (myVersion[0] == NESSUS6[0] && (myVersion[1] < NESSUS6[1] || (myVersion[1] == NESSUS6[1] && myVersion[2] < NESSUS6[2])))
  ) new_vers = string(NESSUS6[0], ".", NESSUS6[1], ".", NESSUS6[2]);
}

#
# If no plugin has shown anything, quietly exit
#
list = get_kb_list("Success/*");
if ( isnull(list) ) exit(0);


if ( ! strlen(nes_ver) )
{
  if ( ! defined_func("pread") && nes_level >= 2202 )
    version = "NeWT";
  else
    version = "Unknown (NASL_LEVEL=" + nes_level + ")";
}
else
  version = nes_ver;

unsupported_version = NULL;
if (!isnull(myVersion) && myVersion[0] < NESSUS6[0])
{
  unsupported_version = 'Your Nessus version ' + version + ' is no longer supported.\n' +
   'Please consider upgrading to ensure that results are complete.\n';
}

if ( new_vers )
 version += " (Nessus " + new_vers + ' is available.)\n';

acas_info = '';
report = 'Information about this scan : \n\n';
report += 'Nessus version : ' + version + '\n';
if (!isnull(unsupported_version))
  report += unsupported_version + '\n';

if ( PLUGIN_SET )
{
 if (  "Home" >< PLUGIN_FEED )
   myPluginFeed = "Nessus Home";
 else
   myPluginFeed = "Nessus";

 report += 'Plugin feed version : ' + PLUGIN_SET     + '\n';
 report += 'Scanner edition used : ' + myPluginFeed + '\n';
 set_kb_item(name: "PluginFeed/Version", value: PLUGIN_SET);
 set_kb_item(name: "PluginFeed/Type", value: PLUGIN_FEED);
 if ( PLUGIN_SET =~ "^[0-9]*$" )
 {
  rel["year"] = int(substr(PLUGIN_SET, 0, 3));
  rel["mon"] = int(substr(PLUGIN_SET, 4, 5));
  rel["mday"] = int(substr(PLUGIN_SET, 6, 7));
  time = ((rel["year"] - 1970)*(24*3600*365)) +
	  (rel["year"] - 1970)/4*24*3600;
  time += (rel["mon"]-1)*(12*3600*30+12*3600*31);
  time += rel["mday"]*(24*3600);
  diff = (unixtime() - time)/3600/24;
  if ( diff >= 30 && diff < 10000 )
  {
   old_feed_alert ++;
   old_feed = string("\nERROR: Your plugins have not been updated since " , rel["year"] , "/" , rel["mon"] , "/" , rel["mday"], "\n",
"Performing a scan with an older plugin set will yield out-of-date results and
produce an incomplete audit. Please run nessus-update-plugins to get the
newest vulnerability checks from Nessus.org.\n\n");
   report += old_feed;
  }
 }
}

n_prod = get_kb_item("nessus/product");
if (!isnull(n_prod))
{
  if (n_prod == PRODUCT_WIN_AGENT  )      scan_type = "Windows Agent";
  else if (n_prod == PRODUCT_UNIX_AGENT ) scan_type = "Unix Agent";
  else if (n_prod == PRODUCT_MAC_AGENT )  scan_type = "Mac Agent";
  else if (n_prod == PRODUCT_NESSUSD    ) scan_type = "Normal";
  else if (n_prod == PRODUCT_NESSUSD_NSX) scan_type = "Nessus in NSX environment";
  else scan_type = "Nessus product undetermined";
  report += 'Scan type : ' + scan_type + '\n';
}

policy_name = get_preference("@internal@policy_name");
if ( strlen(policy_name) > 0 )
{
  acas_info += 'ScanPolicy:' + policy_name;
  report += 'Scan policy used : ' + policy_name + '\n';
}

if (defined_func("report_xml_tag"))
{
  policy_name2 = get_preference("sc_policy_name");
  if (strlen(policy_name2) == 0) policy_name2 = policy_name;
  if (strlen(policy_name2) > 0) report_xml_tag(tag:"policy-used", value:policy_name2);
}

if (get_kb_item("Host/msp_scanner"))
{
  report += 'Scanner IP : tenable.io Scanner\n';
}
else
  report += 'Scanner IP : ' + this_host()    + '\n';

if (!get_kb_item("nessus/product/local"))
{
  list = get_kb_list("Host/scanners/*");
  if ( ! isnull(list) )
  {
   foreach item ( keys(list) )
   {
    item -= "Host/scanners/";
    scanners += item + ' ';
   }

   report += 'Port scanner(s) : ' + scanners + '\n';
  }
  else
   report += '\nWARNING : No port scanner was enabled during the scan. This may\nlead to incomplete results.\n\n';

  if ( get_kb_item("global_settings/disable_service_discovery") )
  {
   report += '\nWARNING: Service discovery has been disabled. The audit is incomplete.\n';
  }

  range = get_preference("port_range");
  if ( ! range ) range = "(?)";
  report += 'Port range : ' + range + '\n';
}

report += 'Thorough tests : ';
if ( thorough_tests ) report += 'yes\n';
else report += 'no\n';

report += 'Experimental tests : ';
if ( experimental_scripts ) report += 'yes\n';
else report += 'no\n';

report += 'Paranoia level : ';
report += report_paranoia + '\n';

report += 'Report verbosity : ';
report += report_verbosity + '\n';

report += 'Safe checks : ';
if ( safe_checks() ) report += 'yes\n';
else report += 'no\n';

report += 'Optimize the test : ';
if ( get_preference("optimize_test") == "yes" ) report += 'yes\n';
else report += 'no\n';

local_checks = FALSE;
login_used = get_kb_item("HostLevelChecks/login");

report += 'Credentialed checks : ';
if ( get_kb_item("Host/local_checks_enabled") )
{
  if ( !get_kb_item("SMB/not_windows") && get_kb_item("Host/windows_local_checks") )
  {
    login_used = get_kb_item("HostLevelChecks/smb_login");
    #
    # Windows local checks are complex because the SMB Login *might* work but
    # access to C$ or the registry could fail
    #
    if ( get_kb_item("SMB/MS_Bulletin_Checks/Possible") )
    {
      local_checks = TRUE;
      report += 'yes';
      if (!isnull(login_used)) report += ", as '" + login_used + "' via SMB";
    }
    else
    {
      systemroot = hotfix_get_systemdrive(as_share:TRUE);
      if (get_kb_item("SMB/Registry/Enumerated") && (!isnull(systemroot) && get_kb_item("SMB/AccessibleShare/"+systemroot)))
      {
        local_checks = TRUE;
        report += 'yes';
        if (!isnull(login_used)) report += ", as '" + login_used + "' via SMB";
      }
      else
      {
        local_checks = FALSE;
        report += 'no';
      }
    }
  }
  else
  {
    # Not windows
    local_checks = TRUE;
    report += 'yes';

    # nb : from ssh_get_info.nasl
    proto_used = get_kb_item("HostLevelChecks/proto");
    if (!isnull(proto_used))
    {
      if (proto_used == 'local')
      {
        report += " (on the localhost)";
      }
      else if (!isnull(login_used))
      {
        report += ", as '" + login_used + "' via " + proto_used;
      }
    }
    # nb: from cisco_ios_version.nasl w/ SNMP
    else if (get_kb_item("Host/Cisco/IOS/Version"))
    {
      report += ", via SNMP";
    }
    # nb: from palo_alto_version.nbin, via REST API.
    else if (get_kb_item("Host/Palo_Alto/Firewall/Source"))
    {
      report += ", via HTTPS";
    }
  }
}
else if ( get_kb_item("SMB/MS_Bulletin_Checks/Possible") && !get_kb_item("Host/patch_management_checks") )
{
  local_checks = TRUE;
  report += 'yes';

  if (!isnull(login_used)) report += " (as '" + login_used + "' via SMB";
}
else report += 'no';
report += '\n';

if (defined_func("report_xml_tag"))
{
  now = unixtime();
  if (local_checks)
  {
    report_xml_tag(tag:"Credentialed_Scan", value:"true");
    report_xml_tag(tag:"LastAuthenticatedResults", value:now);
    acas_info += '\nCredentialed_Scan:true';
    acas_info += '\nLastAuthenticatedResults:' + now;
  }
  else
  {
    report_xml_tag(tag:"Credentialed_Scan", value:"false");
    report_xml_tag(tag:"LastUnauthenticatedResults", value:now);
    acas_info += '\nCredentialed_Scan:false';
    acas_info += '\nLastUnauthenticatedResults:' + now;
  }
}

pmchecks = "";
if (get_kb_item("patch_management/ran"))
{
  tool = "";
  foreach tool (keys(_pmtool_names))
  {
    if (get_kb_item("patch_management/"+tool))
    {
      pmchecks += ", " + _pmtool_names[tool];
      if (local_checks || !tool) pmchecks += " (unused)";
      else tool = _pmtool_names[tool];
    }
  }
}
if (get_kb_item("satellite/ran"))
{
  pmchecks += ", Red Hat Satellite Server";
  if (local_checks) pmchecks += " (unused)";
}
report += 'Patch management checks : ';
if (pmchecks)
{
  pmchecks = substr(pmchecks, 2);
  report += pmchecks + '\n';
}
else report += 'None\n';


report += 'CGI scanning : ';
if (get_kb_item("Settings/disable_cgi_scanning")) report += 'disabled\n';
else report += 'enabled\n';

report += 'Web application tests : ';
if (get_kb_item("Settings/enable_web_app_tests"))
{
 report += 'enabled\n';
 # Display web app tests options
 opt = get_kb_item("Settings/HTTP/test_arg_values");
 report += 'Web app tests -  Test mode : ' + opt + '\n';

 report += 'Web app tests -  Try all HTTP methods : ';
 if (get_kb_item("Settings/HTTP/try_all_http_methods"))
  report += 'yes\n';
 else
  report += 'no\n';

 opt = get_kb_item("Settings/HTTP/max_run_time");
 report += 'Web app tests -  Maximum run time : ' + (int(opt) / 60) + ' minutes.\n';
 opt = get_kb_item("Settings/HTTP/stop_at_first_flaw");
 report += 'Web app tests -  Stop at first flaw : ' + opt + '\n';
}
else report += 'disabled\n';

report += 'Max hosts : ' + get_preference("max_hosts") + '\n';
report += 'Max checks : ' + get_preference("max_checks") + '\n';
report += 'Recv timeout : ' + get_preference("checks_read_timeout") + '\n';

if ( get_kb_item("general/backported")  )
 report += 'Backports : Detected\n';
else
 report += 'Backports : None\n';


post_scan_editing = get_preference("allow_post_scan_editing");
if ( post_scan_editing == "no" )
	report += 'Allow post-scan editing: No\n';
else
	report += 'Allow post-scan editing: Yes\n';

start = get_kb_item("/tmp/start_time");

if ( start )
{
 time = localtime(start);
 if ( time["min"] < 10 ) zero = "0";
 else zero = NULL;

 report += 'Scan Start Date : ' + time["year"] + '/' + time["mon"] + '/' + time["mday"] + ' ' + time["hour"] + ':' + zero + time["min"] + ' ' + getlocaltimezone() + '\n';
}

if ( ! start ) scan_duration = 'unknown';
else           scan_duration = string (unixtime() - start, " sec");
report += 'Scan duration : ' + scan_duration + '\n';

if ( defined_func("report_error") && old_feed_alert )
{
 report_error(title:"Outdated plugins",
	      message:old_feed,
	      severity:1);
}

if(get_preference("sc_disa_output") == "true")
{
  num_unsupported = get_kb_item("NumUnsupportedProducts");
  if(isnull(num_unsupported)) num_unsupported = 0;

  if(num_unsupported > 0)
    report += 'Unsupported products :';

  for (i=0; i<num_unsupported; i++)
  {
    cpe_base = get_kb_item("UnsupportedProducts/"+i+"/cpe_base");
    version = get_kb_item("UnsupportedProducts/"+i+"/version");
    if(version == "unknown")
      report += '\n  UnsupportedProduct:' + cpe_base;
    else
      report += '\n  UnsupportedProduct:' + cpe_base + ':' + version;
  }

  if(num_unsupported > 0) report += '\n';

  report += acas_info;
}

if(get_kb_item("ComplianceChecks/ran"))
{
  if (get_kb_item("ComplianceChecks/scan_info"))
  {
    report += "Compliance checks: " + get_kb_item("ComplianceChecks/scan_info") + '\n';
  }
  else
  {
    report += 'Compliance checks: Yes\n';
  }
}

if ( old_feed_alert && !defined_func("report_error") )
{
 if ( nes_level < 3000 ) security_hole(port:0, data:report);
 else security_hole(port:0, extra:report);
}
else
{
 if ( nes_level < 3000 ) security_note(port:0, data:report);
 else security_note(port:0, extra:report);
}
