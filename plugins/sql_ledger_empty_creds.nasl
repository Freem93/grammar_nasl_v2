#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43404);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2009-4402");
  script_bugtraq_id(37431);
  script_osvdb_id(61337);

  script_name(english:"SQL-Ledger 'admin.pl' Empty Credentials");
  script_summary(english:"Attempts to access 'admin.pl' without credentials");

  script_set_attribute(attribute:"synopsis",value:
"The remote web server is hosting a CGI application that does not
require credentials."
  );
  script_set_attribute(attribute:"description",value:
"The remote web server is hosting SQL-Ledger, a web-based double-entry
accounting system. 

The installed version does not require credentials to access the
administrator interface. 

Note that the installed version is potentially affected by several
other vulnerabilities, though Nessus has not tested for these."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/bugtraq/2007/Mar/147"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Set a strong password for accessing the Administrator interface."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16);
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/12/21"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/12/23"
  );
 script_cvs_date("$Date: 2016/11/17 15:15:44 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_require_ports("Services/www", 80);
  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if (thorough_tests) dirs = list_uniq(make_list("/ledger", "/sql-ledger", cgi_dirs()));
else dirs = make_list(cgi_dirs());

found = FALSE;
foreach dir (dirs)
{
  res = http_send_recv3(method:"GET", item:dir+'/login.pl', port:port);
  if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

  if (
    '<title>SQL-Ledger Version</title>' >< res[2] &&
    '<td class=login align=center><a href="http://www.sql-ledger.org"' >< res[2]
  )
  {
    found = TRUE;
    headers = make_array("Content-Type", "application/x-www-form-urlencoded");
    postdata = 'password=&action=Login&path=bin%2Fmozilla';
    req = http_mk_post_req(
      port:port,
      item:dir+'/admin.pl',
      add_headers:headers,
      data:postdata
    );

    res = http_send_recv_req(port:port, req:req);
    if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

    if (
      '<title>SQL-Ledger Accounting Administration - </title>' >< res[2] &&
      'To add a user to a group edit a name, change the login name and save' >< res[2]
    )
    {
      if (report_verbosity > 0)
      {
        req_str = http_mk_buffer_from_req(req:req);
        report =
          '\n'+
          'Nessus was able to gain access to the administrative interface using\n'+
          'the following request :\n'+
          '\n'+
          '  '+str_replace(find:'\n', replace:'\n  ', string:req_str)+'\n'+
          '\n';
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      exit(0);
    }
  }
}
if (!found) exit(0, 'The host is not affected because SQL-Ledger was not detected on port '+port+'.');
else exit(0, 'The host is not affected because the SQL-Ledger administrative interface on port '+port+' requires credentials.');
