#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59757);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/06 17:22:01 $");

  script_cve_id("CVE-2012-0304");
  script_bugtraq_id(53903);
  script_osvdb_id(81902);
  script_xref(name:"TRA", value:"TRA-2012-04");

  script_name(english:"Symantec LiveUpdate Administrator < 2.3.2 Privilege Escalation (SYM12-009)");
  script_summary(english:"Checks LUA version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote host has a privilege escalation
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of LiveUpdate Administrator running on the remote host is
earlier than 2.3.2.  Such versions have a privilege escalation
vulnerability due to insecure file permissions set by a default
installation. 

The webapps directory allows write access to the Everyone group.
A local, unprivileged attacker could exploit this by creating
or modifying files that will be executed as SYSTEM, resulting in
privilege escalation."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2012-04");
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.symantec.com/docs/TECH155523"
  );
   # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2012&suid=20120615_00
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f93f8d81"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to LiveUpdate Administrator 2.3.2 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2012/05/28");
  script_set_attribute(attribute:"patch_publication_date",value:"2011/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/28");

  script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:liveupdate_administrator");
  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("symantec_lua_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/symantec_lua");
  script_require_ports("Services/www", 7070, 8080);

  exit(0);
}


include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:7070);
install = get_install_from_kb(appname:'symantec_lua', port:port, exit_on_fail:TRUE);

dir = install['dir'];
ver = install['ver'];
url = build_url(port:port, qs:dir);

if (ver == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "Symantec LiveUpdate Administrator", url);

fix = '2.3.2';
if (ver_compare(ver:ver, fix:fix, strict:FALSE) != -1)
  audit(AUDIT_LISTEN_NOT_VULN, "Symantec LiveUpdate Administrator", port, ver);

if (report_verbosity > 0)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix + '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
