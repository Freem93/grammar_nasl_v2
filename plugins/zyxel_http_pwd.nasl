#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17304);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2014/05/21 17:15:44 $");
  script_bugtraq_id(6671);
  script_osvdb_id(592, 14758);

  script_cve_id("CVE-2001-1135", "CVE-1999-0571");

  script_name(english:"ZyXEL Routers Default Web Account");
  script_summary(english:"Logs into the ZyXEL web administration");

  script_set_attribute(attribute:"synopsis", value:"The remote host is a router that uses a default web password.");
  script_set_attribute(attribute:"description", value:
"The remote host is a ZyXEL router with a default password set.  An
attacker could connect to the web interface and reconfigure it.");
  script_set_attribute(attribute:"solution", value:"Change the password immediately.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports(80);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_http_port(default:80, embedded: 1);
# if ( ! port || port != 80 ) exit(0);

banner = get_http_banner(port:port);
if ( "ZyXEL-RomPager" >!< banner ) exit(0, "The web server listening on port "+port+" does not look like a ZyXEL web interface.");

r = http_send_recv3(port: port, method: "GET", item: "/", username: "", password: "", exit_on_fail:TRUE);
if (r[0] !~ "^HTTP/1\.[01] +401 ") exit(0, "The ZyXEL web interface listening on port "+port+" does not require credentials.");

r = http_send_recv3(method: "GET", port: port, item: "/", username: "admin", password: "1234", exit_on_fail:TRUE);

if (r[0] =~ "^HTTP/1\.[01] +200 ")
{
  security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "ZyXEL web interface", port);
