#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100159);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/05/12 21:34:26 $");

  script_cve_id(
    "CVE-2017-5810",
    "CVE-2017-5811",
    "CVE-2017-5812",
    "CVE-2017-5813",
    "CVE-2017-5814"
  );
  script_bugtraq_id(98331);
  script_osvdb_id(
    157030,
    157031,
    157032,
    157033,
    157034
  );
  script_xref(name:"HP", value:"HPESBGN03740");
  script_xref(name:"IAVB", value:"2017-B-0052");
  script_xref(name:"ZDI", value:"ZDI-17-330");
  script_xref(name:"ZDI", value:"ZDI-17-331");
  script_xref(name:"ZDI", value:"ZDI-17-332");

  script_name(english:"HP Network Automation 9.x, 10.x < 10.00.022 / 10.1x.x < 10.11.03 / 10.20.x < 10.21.01 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of HP Network Automation.");

  script_set_attribute(attribute:"synopsis",value:
"An application running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The HP Network Automation application running on the remote host is
version 9.1x, 9.2x, or 10.00.x prior to 10.00.022; 10.10.x or 10.11.x
prior to 10.11.03; or 10.20.x prior to 10.21.01. It is, therefore,
affected by multiple vulnerabilities :

  - A SQL injection vulnerability exists in the
    RedirectServlet component due to improper sanitization
    of user-supplied input. An unauthenticated, remote
    attacker can exploit this to inject or manipulate SQL
    queries in the back-end database, resulting in the
    manipulation or disclosure of arbitrary data.
    (CVE-2017-5810)

  - An information disclosure vulnerability exists in the
    TrueControl Management Engine service due a path
    traversal flaw caused by improper sanitization of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this, via a specially created request, to
    read arbitrary files. (CVE-2017-5811)

  - An authentication bypass vulnerability exists in the
    PermissionFilter class due to a path traversal flaw
    caused by improper sanitization of user-supplied input.
    An unauthenticated, remote attacker can exploit this,
    via a specially crafted request, to bypass
    authentication and gain access to an associated servlet.
    (CVE-2017-5812)

  - An unspecified flaw exists that allows an
    unauthenticated, remote attacker to bypass security
    controls and gain unauthorized access. (CVE-2017-5813)

  - An unspecified flaw exists that allows an
    unauthenticated, remote attacker to bypass
    authentication checks. (CVE-2017-5814)");
  # https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbgn03740en_us
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?422ea350");
  script_set_attribute(attribute:"solution",value:
"Upgrade to HP Network Automation version 10.00.022 / 10.11.03 /
10.21.01 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date",value:"2017/05/04");
  script_set_attribute(attribute:"patch_publication_date",value:"2017/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/12");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:hp:network_automation");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("hp_network_automation_detect.nbin");
  script_require_keys("installed_sw/HP Network Automation");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app_name = "HP Network Automation";
get_install_count(app_name:app_name, exit_if_zero:TRUE);

port    = get_http_port(default:443);
install = get_single_install(app_name:app_name, port:port, exit_if_unknown_ver:TRUE);
version = install['version'];
url     = build_url(port:port,qs:install['path']);

fix = NULL;
vuln = FALSE;

# 9.1x or v9.2x should upgrade to v10.0x, or v10.1x or v10.2x
if (version =~ "^9\.[1-2][0-9](\.|$)")
{
  fix = "10.0x / 10.1x / 10.2x";
  vuln = TRUE;
}
else if (version =~ "^10\.00(\.|$)")
{
  fix = "10.00.022";
}
else if (version =~ "^10\.1[0-1](\.|$)")
{
  fix = "10.11.03";
}
else if (version =~ "^10\.2[0-1](\.|$)")
{
  fix = "10.21.01";
}

if (isnull(fix))
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url, version);

if (!vuln)
{
  if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0 )
  vuln = TRUE;
}

if (vuln)
{
  items = make_array("URL", url,
                     "Installed version", version,
                     "Fixed version", fix
                    );
  order = make_list("URL", "Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url, version);
