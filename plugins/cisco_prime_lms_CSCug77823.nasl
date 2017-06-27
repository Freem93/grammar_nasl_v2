#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70258);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/04 18:02:13 $");

  script_cve_id("CVE-2013-5482");
  script_bugtraq_id(62366);
  script_osvdb_id(97238);
  script_xref(name:"CISCO-BUG-ID", value:"CSCug77823");

  script_name(english:"Cisco Prime LAN Management Solution Cross-Frame Scripting");
  script_summary(english:"Checks for Cisco Prime LMS workaround");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a network management application installed that is
potentially affected by a cross-frame scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Cisco Prime LAN Management Solution installed on the
remote host is affected by a cross-frame scripting vulnerability due to
insufficient filtering of user-supplied input.  An attacker could
leverage this to direct a user to an attacker controlled page and
conduct clickjacking or various other client-side browser attacks."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2013-5482
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f7c54cca");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 4.2(4) or refer to the vendor-supplied link for a
suggested workaround."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_lan_management_solution");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_prime_lms_web_detect.nasl");
  script_require_ports("Services/www", 443);
  script_require_keys("www/cisco_lms");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:443);
app = "Cisco Prime LAN Management Solution";

install = get_install_from_kb(
  appname : "cisco_lms",
  port    : port,
  exit_on_fail : TRUE
);
version = install["ver"];

loginpage = get_kb_item_or_exit('/tmp/cisco_lms/' +port+ '/loginpage');
report_url = build_url(qs:loginpage, port:port);
vuln = FALSE;

# nb: The security vulnerability applies to the following combinations
# 4.1 Base | 4.2 .1, .2, .3, Base
if (
  version =~ "^4\.(1|2(\.[0-3]+)*)($|[^0-9\.])" ||
  version ==  UNKNOWN_VER
)
{
  res = http_send_recv3(
    method : "GET",
    item   : loginpage,
    port   : port,
    exit_on_fail : TRUE
  );

  # This header should be displayed on patched versions or versions in which
  # the workaround was applied
  if (!egrep(pattern:"X-Frame-Options: SAMEORIGIN", string:res[1], icase:TRUE)) vuln = TRUE;
}
if (!vuln) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, report_url);

set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
if (report_verbosity > 0)
{
  report =
    '\n' + 'Nessus was able to verify the issue exists by requesting the following '+
    '\n' + 'URL and examining the response header :' +
    '\n' +
    '\n' + report_url +
    '\n';
  if (report_verbosity > 1)
  {
    report +=
     '\n' + 'This produced the following output which does not reflect the workaround' +  
     '\n' + 'for the X-Frame-Options header :' +
     '\n' +
     '\n' + chomp(res[1]) +
     '\n';
  }
  security_warning(port:port, extra:report);
}
else security_warning(port);
