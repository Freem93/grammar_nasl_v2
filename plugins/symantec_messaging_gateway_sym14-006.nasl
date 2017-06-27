#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73690);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/08 04:42:34 $");

  script_cve_id("CVE-2014-1648");
  script_bugtraq_id(66966);
  script_osvdb_id(106171);

  script_name(english:"Symantec Messaging Gateway 10.x < 10.5.2 Management Console XSS (SYM14-006)");
  script_summary(english:"Checks SMG version number");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A messaging security application running on the remote host has
a cross-site scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the version of
Symantec Messaging Gateway running on the remote host is 10.x less than
10.5.2, and is therefore affected by a cross-site scripting vulnerability.

A cross-site scripting flaw exists in the
'brightmail/setting/compliance/DlpConnectFlow$view.flo' within the
management console. The flaw could allow a context-dependent attacker,
with a specially crafted request, to execute arbitrary script code
within the browser and server trust relationship.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number."
  );
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20140422_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a25abec9");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2014/Apr/256");
  script_set_attribute(attribute:"solution", value:"Upgrade to Symantec Messaging Gateway 10.5.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:messaging_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("symantec_messaging_gateway_detect.nasl");
  script_require_keys("www/sym_msg_gateway");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:443);
install = get_install_from_kb(appname:'sym_msg_gateway', port:port, exit_on_fail:TRUE);
base_url = build_url(qs:install['dir'], port:port);

if (install['ver'] == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_WEB_APP_VER, 'Symantec Messaging Gateway', base_url);
if (install['ver'] !~ "^10(\.|$)")
  audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Symantec Messaging Gateway', base_url, install['ver']);
if (install['ver'] =~ "^10(\.5)?$") audit(AUDIT_VER_NOT_GRANULAR, 'Symantec Messaging Gateway', port, install['ver']);

if (
  install['ver'] =~ "^10\.[0-4]($|[^0-9])" ||
  install['ver'] =~ "^10\.5\.[01]($|[^0-9])"
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + base_url +
      '\n  Installed version : ' + install['ver'] +
      '\n  Fixed version     : 10.5.2\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Symantec Messaging Gateway', base_url, install['ver']);
