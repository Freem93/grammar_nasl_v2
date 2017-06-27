#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80118);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/19 18:02:20 $");

  script_cve_id("CVE-2014-7285");
  script_bugtraq_id(71620);
  script_osvdb_id(116009);

  script_name(english:"Symantec Web Gateway < 5.2.2 Authenticated OS Command Injection (SYM14-016)");
  script_summary(english:"Checks the SWG version.");

  script_set_attribute(attribute:"synopsis", value:
"A web security application hosted on the remote web server is affected
by a OS command injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote web server
is hosting a version of Symantec Web Gateway prior to version 5.2.2.
It is, therefore, affected by a operating system (OS) command
injection vulnerability in an unspecified PHP script which impacts the
management console. A remote, authenticated user can exploit this
issue to execute arbitrary OS commands subject to the privileges of
the authenticated user.");
  script_set_attribute(attribute:"see_also", value:"http://karmainsecurity.com/KIS-2014-19");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20141216_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2f3741bb");
  script_set_attribute(attribute:"solution", value:"Upgrade to Symantec Web Gateway 5.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Symantec Web Gateway 5 restore.php Post Authentication Command Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:web_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("symantec_web_gateway_detect.nasl");
  script_require_keys("installed_sw/symantec_web_gateway");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:443, php:TRUE);
app = 'Symantec Web Gateway';

install = get_single_install(
  app_name : 'symantec_web_gateway',
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
ver = install['version'];
url = build_url(port:port, qs:dir);

fix = '5.2.2';

if (ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, ver);
