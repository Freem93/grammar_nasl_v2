#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(68933);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/10/27 15:03:55 $");

  script_cve_id("CVE-2013-4883");
  script_bugtraq_id(61422);
  script_osvdb_id(95187, 95188, 95189, 95190, 95191);
  script_xref(name:"EDB-ID", value:"26807");

  script_name(english:"McAfee ePolicy Orchestrator < 4.6.7 Multiple XSS");
  script_summary(english:"ePO App Server version check");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A security management application on the remote host has multiple
cross-site scripting vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version, the version of McAfee ePolicy
Orchestrator (ePO) running on the remote host is 4.6.6 or earlier, and
therefore, has multiple reflected cross-site scripting vulnerabilities. 
An attacker could exploit any of these issues by tricking a user into
requesting a specially crafted URL, resulting in arbitrary script code
execution."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2013/Jul/80");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=KB78824");
  script_set_attribute(
    attribute:"solution",
    value:
"There is no solution available at this time.

McAfee plans on fixing these vulnerabilities in ePO version 4.6.7, which
is scheduled to be released in late Q3 2013."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_epo_app_server_detect.nasl");
  script_require_keys("www/epo_app_server");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8443);
install = get_install_from_kb(appname:'epo_app_server', port:port, exit_on_fail:TRUE);
dir = install['dir'];
ver = install['ver'];
url = build_url(qs:dir, port:port);

# this should never be true but this code will be defensive anyway
if (ver == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_WEB_APP_VER, 'ePO Application Server', url);

# KB78824 says 4.6.6 and earlier are affected.  It doesn't explicitly
# say that only 4.6.x is affected, so the plugin will flag all earlier versions
fix = '4.6.7';
if (ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, 'ePO Application Server', url, ver);

set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix + ' (release scheduled for late Q3 2013)\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
