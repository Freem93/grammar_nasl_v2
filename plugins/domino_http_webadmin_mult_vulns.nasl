#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71177);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/09/24 21:08:38 $");

  script_cve_id("CVE-2013-4050", "CVE-2013-4051", "CVE-2013-4055");
  script_bugtraq_id(63576, 63577, 63578);
  script_osvdb_id(99509, 99510, 99511);

  script_name(english:"IBM Domino Web Administrator Multiple Vulnerabilities");
  script_summary(english:"Checks for webadmin.nsf");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote IBM Domino web server includes IBM Domino Web Administrator
(webadmin.nsf) and is affected by multiple vulnerabilities :

  - An authenticated user can exploit an unspecified cross-
    site request forgery (CSRF) vulnerability by enticing
    a user to follow a specially crafted URL.
    (CVE-2013-4050)

  - An unspecified cross-site scripting vulnerability exists
    that can be exploited by an authenticated user.
    (CVE-2013-4051)

  - An unspecified cross-site scripting vulnerability exists
    that can be exploited by an authenticated user.
    (CVE-2013-4055)

Note that only versions 8.5.x and 9.0.x of IBM Domino are affected by
these issues. 

Further note that Nessus has not tested for the vulnerabilities
directly but has instead checked to see if the Domino Web Administrator
(webadmin.nsf) is accessible."
  );
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_for_safer_administration_of_ibm_domino_server_use_domino_administrator_client_instead_of_domino_web_administrator?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f8e785d8");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21652988");
  script_set_attribute(attribute:"solution", value:
"Domino Web Administrator has been deprecated.  Refer to the vendor-
supplied URL for remediation recommendations.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_domino");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("domino_installed.nasl");
  script_require_keys("www/domino");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

get_kb_item_or_exit("www/domino");

found = FALSE;
ver = get_kb_item("Domino/Version");

# Domino Web Administrator versions 8.5.x and 9.0.x are affected
# so check Domino server version to determine if we should check
# for webadmin.nsf
if (
  ver =~ "^(8\.5|9)([^0-9]|$)" ||
  (ver == UNKNOWN_VER && report_paranoia == 2)
)
{
  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : "/webadmin.nsf",
    exit_on_fail : TRUE
  );

  if (
    res[0] =~ "401 Unauthorized" &&
    "You are not authorized to perform this" >< res[2]
  ) found = TRUE;
  else if (
    res[0] =~ "500 Internal Server Error" &&
    "You are not authorized to access that database" >< res[2]
  ) found = TRUE;
}

if (!found) audit(AUDIT_WEB_APP_NOT_AFFECTED, "IBM Domino", build_url(qs:"/", port:port));

set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);
set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

if (report_verbosity > 0)
{
  header = 'Nessus was able to verify this issue with the following URL';
  report = get_vuln_report(
    items  : "/webadmin.nsf",
    port   : port,
    header : header
  );
  security_warning(port:port, extra:report);
}
else security_warning(port);
