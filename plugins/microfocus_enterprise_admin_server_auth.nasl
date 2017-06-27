#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(51839);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/09/24 21:17:12 $");

  script_name(english:"Micro Focus Enterprise Administration Server Authentication Check");
  script_summary(english:"Checks if Administration Server interface requires authorization.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Micro Focus Enterprise Administration Server interface
does not require authentication."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The administration interface for the remote Micro Focus Enterprise
Server is accessible without authentication.  A remote attacker is
able to access potentially sensitive information and modify any
settings available through this administration interface."
  );
  script_set_attribute(attribute:"solution", value:"Modify the application's security settings to require authentication.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("microfocus_enterprise_admin_server_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 86);
  script_require_keys("www/microfocus_ent_admin_server");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:86);

install = get_install_from_kb(
  appname      : 'microfocus_ent_admin_server',
  port         : port,
  exit_on_fail : TRUE
);

clear_cookiejar();
url = install['dir'] + '/';

r = http_send_recv3(
  item         : url,
  port         : port,
  method       : "GET",
  exit_on_fail : TRUE
);

s_val   = "";
mf_val  = "";
cpat    = "MF_CLIENT=([^;]*)";
headers = parse_http_headers(status_line:r[0], headers:r[1]);

if (!isnull(headers) && headers['set-cookie'] && headers['mf-cookie-1'])
{
  s_matches = eregmatch(string:headers['set-cookie'], pattern:cpat);
  if (s_matches)
  {
    s_val = s_matches[1];
    s_val = str_replace(string:s_val, find:" ", replace:"");
  }

  mf_matches  = eregmatch(string:headers['mf-cookie-1'], pattern:cpat);
  if (mf_matches)
  {
    mf_val = mf_matches[1];
    mf_val = str_replace(string:mf_val, find:" ", replace:"");
  }
}

if ((mf_val == s_val) && (strlen(s_val) > 0))
{
  if (report_verbosity > 0)
  {
    header =
      "Nessus was able to gain unauthenticated access as the user '" +
      s_val +
      "' using the following URL";

    report = get_vuln_report(
      header : header,
      items  : url,
      port   : port
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, 'The remote Micro Focus Enterprise Administration Server install at '+build_url(qs:url, port:port)+ ' requires authentication.');
