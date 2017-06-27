#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66037);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/06/23 19:48:37 $");

  script_cve_id("CVE-2013-2766");
  script_bugtraq_id(59038);
  script_osvdb_id(91682);

  script_name(english:"Splunk 4.3.x < 4.3.6 Unspecified XSS");
  script_summary(english:"Checks the version of Splunk.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains an application that is affected by a
cross-site scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version number, the Splunk Web hosted on the remote
web server is affected by a cross-site scripting vulnerability due to
a failure to properly sanitize unspecified user-supplied input before
returning it to the user. An unauthenticated, remote attacker can
exploit this issue to inject arbitrary HTML or script code into a
user's browser to be executed within the security context of the
affected site."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.splunk.com/view/SP-CAAAHSQ");
  script_set_attribute(attribute:"see_also", value:"http://docs.splunk.com/Documentation/Splunk/4.3.6/ReleaseNotes/4.3.6");
  script_set_attribute(attribute:"solution", value:"Upgrade to Splunk 4.3.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("splunkd_detect.nasl","splunk_web_detect.nasl");
  script_require_ports("Services/www", 8089, 8000);
  script_require_keys("installed_sw/Splunk");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Splunk";

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8000, embedded:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
ver = install['version'];

install_url = build_url(qs:dir, port:port);

if (ver =~ "^4\.3\." && ver_compare(ver:ver,fix:"4.3.6",strict:FALSE) < 0)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +ver+
      '\n  Fixed version     : 4.3.6\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, ver);
