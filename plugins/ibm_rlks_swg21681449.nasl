#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77710);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/09/16 20:31:30 $");

  script_cve_id("CVE-2014-0909", "CVE-2014-3079", "CVE-2014-4756");
  script_bugtraq_id(69642, 69643, 69645);
  script_osvdb_id(110768, 110769, 110770);

  script_name(english:"IBM Rational License Key Server Administration and Reporting Tool 8.1.4.x < 8.1.4.4 Multiple Vulnerabilities");
  script_summary(english:"Checks the software version.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version 8.1.4.x of IBM Rational License
Key Server Administration and Reporting Tool (RLKS) that is prior to
8.1.4.4. It is, therefore, affected by multiple vulnerabilities :

  - The secure flag for session cookies is not properly set
    when in SSL mode. An attacker can exploit this
    vulnerability to capture sensitive information from a
    cookie by intercepting its transmission. (CVE-2014-0909)

  - An information disclosure vulnerability exists that
    allows an attacker to gain access to license usage data
    by using a specially crafted SPARQL query.
    (CVE-2014-3079)

  - An unspecified vulnerability exists that is related to
    user session cookies, which an attacker can exploit to
    impersonate a legitimate user. (CVE-2014-4756)");
  script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/support/docview.wss?uid=swg21681449");
  script_set_attribute(attribute:"solution", value:"Upgrade to Rational License Key Server Fix Pack 4 (8.1.4.4) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:rational_license_key_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("ibm_rlks_administration_reporting_tool.nbin");
  script_require_keys("installed_sw/IBM Rational License Key Server Administration and Reporting Tool");
  script_require_ports("Services/www", 4743);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:4743);

app = "IBM Rational License Key Server Administration and Reporting Tool";

get_install_count(app_name:app, exit_if_zero:TRUE);

install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);

version = install['version'];
path = install['path'];
install_url = build_url(port:port, qs:path);

fix = "8.1.4.4";
if (
  version =~ "^8\.1\.4$" ||
  (version =~ "^8\.1\.4\." && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Fixed version     : ' + fix +
             '\n  Install path      : ' + install_url + 
             '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
