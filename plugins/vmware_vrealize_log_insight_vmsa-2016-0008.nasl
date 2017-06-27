#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92841);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/29 20:13:37 $");

  script_cve_id("CVE-2016-2081", "CVE-2016-2082");
  script_bugtraq_id(91136);
  script_osvdb_id(140056, 140057);
  script_xref(name:"VMSA", value:"2016-0008");

  script_name(english:"VMware vRealize Log Insight 2.x / 3.x < 3.3.2 Multiple Vulnerabilities (VMSA-2016-0008)");
  script_summary(english:"Checks the version of VMware vRealize Log Insight.");

  script_set_attribute(attribute:"synopsis", value:
"A log management application running on the remote host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The VMware vRealize Log Insight application running on the remote host
is 2.x or 3.x prior to 3.3.2. It is, therefore, affected by multiple
vulnerabilities :

  - A cross-site scripting (XSS) vulnerability exists due to
    improper validation of user-supplied input before
    returning it to users. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    request, to execute arbitrary script code in a user's
    browser session. (CVE-2016-2081)

  - A cross-site request forgery (XSRF) vulnerability exists
    due to a failure to require multiple steps, explicit
    confirmation, or a unique token when performing certain
    sensitive actions. An unauthenticated, remote attacker
    can exploit this, by convincing a user to follow a
    specially crafted link, to hijack the authentication of
    the user and replace trusted content in the UI.
    (CVE-2016-2082)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2016-0008");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2016/000332.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vRealize Log Insight version 3.3.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/10");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vrealize_log_insight");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("vmware_vrealize_log_insight_webui_detect.nbin");
  script_require_ports("installed_sw/VMware vRealize Log Insight");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");
include("webapp_func.inc");

app = "VMware vRealize Log Insight";
fix = "3.3.2";

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:443);
install = get_single_install(app_name:app, port:port);

version = install['version'];
install_url = build_url2(port:port, qs:install['path']);

if (version == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_WEB_APP_VER, app, install_url);

# only 2.x, 3.x
if (version !~ "^[23]($|\.)")
  audit(AUDIT_INST_VER_NOT_VULN, app, version);

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  order = make_list("URL", "Installed version", "Fixed version");
  report = make_array(
    order[0], install_url,
    order[1], version,
    order[2], fix
  );
  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report, xss:TRUE, xsrf:TRUE);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, version);
