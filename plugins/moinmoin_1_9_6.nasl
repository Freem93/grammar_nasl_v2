#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64930);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/28 21:52:56 $");

  script_cve_id("CVE-2012-6080", "CVE-2012-6081", "CVE-2012-6082");
  script_bugtraq_id(57082, 57147, 57076, 57089);
  script_osvdb_id(88825, 88826, 88827, 88828);

  script_name(english:"MoinMoin < 1.9.6 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of MoinMoin");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A wiki application on the remote web server is affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version number, the MoinMoin install hosted on the
remote web server is affected by multiple vulnerabilities:

  - Versions 1.9.3 up to 1.9.5 are affected by a directory
    traversal vulnerability because the _do_attachment_move
    action in 'AttachFile.py' does not properly sanitize
    user-supplied input.  This could allow an
    unauthenticated, remote attacker to upload and
    overwrite arbitrary files on the remote host.
    (CVE-2012-6080)

  - Versions 1.9.x up to 1.9.5 are affected by a remote
    code execution vulnerability because the 'twikidraw.py'
    action fails to properly sanitize user-supplied input.
    A remote, unauthenticated attacker could utilize a
    specially crafted request using directory traversal
    style characters to upload a file containing arbitrary
    code to the remote host.  An attacker could then execute
    the code with the privileges of the user that runs the
    MoinMoin process.  (CVE-2012-6081)

  - Version 1.9.5 is affected by a cross-site scripting
    (XSS) vulnerability because the application fails to
    properly sanitize user-supplied input in the 'page_name'
    parameter when creating an rss link.  An attacker could
    leverage this issue to inject arbitrary HTML and script
    code into a user's browser to be executed within the
    security context of the affected site.  (CVE-2012-6082)

  - Versions < 1.9.x are not maintained by MoinMoin
    developers and should be considered vulnerable.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number."
  );
  script_set_attribute(attribute:"see_also", value:"http://moinmo.in/SecurityFixes");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.9.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"MoinMoin 1.9.5 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MoinMoin twikidraw Action Traversal File Upload');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:moinmo:moinmoin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("moinmoin_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/moinmoin", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

install = get_install_from_kb(
  appname:"moinmoin",
  port:port,
  exit_on_fail:TRUE
);

dir = install["dir"];
version = install["ver"];
install_url = build_url(qs:dir, port:port);

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "MoinMoin", install_url);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Versions less than 1.9.6 are vulnerable
# http://moinmo.in/SecurityFixes notes that versions < 1.9.x are no longer
# maintained and should be considered vulnerable
if (
  ver[0] < 1 ||
  (ver[0] == 1 && ver[1] < 9) ||
  (ver[0] == 1 && ver[1] == 9 && ver[2] < 6)
)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 1.9.6\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "MoinMoin", install_url, version);
