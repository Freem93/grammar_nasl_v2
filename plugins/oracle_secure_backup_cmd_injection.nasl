#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55668);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/02 14:37:08 $");

  script_cve_id("CVE-2011-2261");
  script_bugtraq_id(48752);
  script_osvdb_id(73920);
  script_xref(name:"TRA", value:"TRA-2011-05");

  script_name(english:"Oracle Secure Backup Administration Server login.php uname Parameter Arbitrary Command Injection");
  script_summary(english:"Fingerprints the patch based on server response");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP script that allows execution of
arbitrary commands."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Oracle Secure Backup Administration Server running on
the remote host fails to adequately sanitize user-supplied input to
the 'uname' parameter of 'login.php'.  The system performs some
sanitization which limits exploitation of this issue, but code
execution is still possible.

A remote, unauthenticated attacker could exploit this to execute code
on the remote host with the privileges of the web server user.

By default the server runs with SYSTEM privileges under Windows."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2011-05");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-238/");
  script_set_attribute(attribute:"see_also",value:"http://seclists.org/bugtraq/2011/Jul/138");
   # http://www.oracle.com/technetwork/topics/security/cpujuly2011-313328.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?a7c55943");
  script_set_attribute(attribute:"solution", value:"Apply the patch referenced in Oracle's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:secure_backup");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 443);
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:443, php:TRUE);

# unpatched systems will consider the leading space valid,
# patched systems will consider it invalid
url = '/login.php?attempt=1&uname=%20' + unixtime();
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

# Make sure it looks like OSB first
if ('<title>Oracle Secure Backup Web Interface</title>' >!< res[2])
  exit(0, 'Oracle Secure Backup is not running on port ' + port + '.');

# Then check if the patch is missing
if ('login incorrect.</td>' >< res[2])
{
  if (report_verbosity > 0)
  {
    header =
      'The system allowed a login attempt for a username with invalid characters.\n' +
      'This indicates the system is unpatched.  Nessus verified this by making the\n' +
      'following request';
    report = get_vuln_report(header:header, items:url, port:port);
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else if ('login failed</td>' >< res[2]) exit(0, 'The host is not affected on port ' + port + '.');
else exit(1, 'Unexpected response on port ' + port + '.');
