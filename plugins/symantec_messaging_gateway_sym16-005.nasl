#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90919);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/07/11 13:16:00 $");

  script_cve_id(
    "CVE-2016-2203",
    "CVE-2016-2204"
  );
  script_bugtraq_id(
    86137,
    86138
  );
  script_osvdb_id(
    137388,
    137389
  );
  script_xref(name:"EDB-ID", value:"39715");

  script_name(english:"Symantec Messaging Gateway 10.x < 10.6.1 Management Console Multiple Vulnerabilities (SYM16-005)");
  script_summary(english:"Checks the Symantec Messaging Gateway version number.");

  script_set_attribute(attribute:"synopsis", value:
"A messaging security application running on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Symantec Messaging
Gateway (SMG) running on the remote host is 10.x prior to 10.6.1. It
is, therefore, affected by multiple vulnerabilities :

  - A privilege escalation vulnerability exists in the SMG
    management console due to AD password information being
    insecurely stored and encrypted. A local attacker who
    has read-level access can exploit this, by reverse
    engineering the encrypted AD password, to gain
    unauthorized, elevated access to additional resources on
    the network. Note that recovery of this password would
    not provide any additional access to the SMG appliance
    itself. (CVE-2016-2203)

  - A privilege escalation vulnerability exists due to an
    unspecified flaw in the SMG management console. A local
    attacker can exploit this, by manipulating code input to
    the terminal window, to gain access to the privileged
    root shell of the console. (CVE-2016-2204)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20160418_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c5e65315");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Messaging Gateway version 10.6.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:messaging_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("symantec_messaging_gateway_detect.nasl");
  script_require_keys("www/sym_msg_gateway");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

get_install_count(app_name:'sym_msg_gateway', exit_if_zero:TRUE);

port = get_http_port(default:443);
install = get_single_install(app_name:'sym_msg_gateway', port:port);
base_url = build_url(qs:install['dir'], port:port);

if (install['version'] == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_WEB_APP_VER, 'Symantec Messaging Gateway', base_url);
if (install['version'] !~ "^10(\.|$)")
  audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Symantec Messaging Gateway', base_url, install['version']);
if (install['version'] =~ "^10(\.6)?$") audit(AUDIT_VER_NOT_GRANULAR, 'Symantec Messaging Gateway', port, install['version']);

if (
  install['version'] =~ "^10\.[0-5]($|[^0-9])" ||
  install['version'] =~ "^10\.6\.0($|[^0-9])"
)
{
  report =
    '\n  URL               : ' + base_url +
    '\n  Installed version : ' + install['version'] +
    '\n  Fixed version     : 10.6.1\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Symantec Messaging Gateway', base_url, install['version']);
