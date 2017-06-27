#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63066);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/08/16 14:42:21 $");

  script_bugtraq_id(56610);
  script_osvdb_id(87619);
  script_xref(name:"CERT", value:"849841");
  script_xref(name:"IAVB", value:"2012-B-0117");

  script_name(english:"Symantec Messaging Gateway 9.5.x Multiple Vulnerabilities (SYM12-018)");
  script_summary(english:"Checks SMG version number");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A messaging security application running on the remote host has
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the version of Symantec
Messaging Gateway running on the remote host is 9.5.x and is, therefore,
affected by multiple vulnerabilities that could be exploited by a
remote, unauthenticated attacker to crash the affected service."
  );
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20121120_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84141df1");
  script_set_attribute(attribute:"solution", value:"Upgrade to Symantec Messaging Gateway 10.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:messaging_gateway");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

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
if (install['ver'] !~ "^9\.5(\.|$)")
  audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Symantec Messaging Gateway', base_url, install['ver']);

if (report_verbosity > 0)
{
  report =
    '\n  URL               : ' + base_url +
    '\n  Installed version : ' + install['ver'] +
    '\n  Fixed version     : 10.0.1\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
