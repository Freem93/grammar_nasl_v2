#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71494);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/21 22:04:46 $");

  script_cve_id("CVE-2013-4842", "CVE-2013-4843");
  script_bugtraq_id(63689, 63691);
  script_osvdb_id(99688, 99689);

  script_name(english:"iLO 3 < 1.65 / iLO 4 < 1.32 Multiple Vulnerabilities");
  script_summary(english:"Checks version of HP Integrated Lights-Out (iLO).");

  script_set_attribute(attribute:"synopsis", value:
"The remote HP Integrated Lights-Out (iLO) server's web interface is
affected by multiple vulnerabilities.") ;
  script_set_attribute(attribute:"description", value:
"According to its version number, the remote HP Integrated Lights-Out
(iLO) server is affected by the following vulnerabilities :

  - An unspecified error exists that could allow cross-
    site scripting attacks. (CVE-2013-4842 / SSRT101323)

  - An unspecified error exists that could allow an
    attacker to obtain sensitive information.
    (CVE-2013-4843 / SSRT101326)");

  # http://h20566.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c03996804-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5fab8bbe");
  script_set_attribute(attribute:"solution", value:
"For HP Integrated Lights-Out (iLO) 3 upgrade firmware to 1.65 or later. 
For iLO 4, upgrade firmware to 1.32 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:integrated_lights-out_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("ilo_detect.nasl");
  script_require_keys("Settings/ParanoidReport", "www/ilo", "ilo/generation", "ilo/firmware");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

# Each generation has its own series of firmware version numbers.
generation = get_kb_item_or_exit("ilo/generation");

# The version is tied to the firmware and not specific to the web interface.
version = get_kb_item_or_exit("ilo/firmware");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, embedded:TRUE);

install = get_install_from_kb(
  appname      : "ilo",
  port         : port,
  exit_on_fail : TRUE
);
install_url = build_url(port:port, qs:install["dir"]);

# Firmware is unique to the generation of iLO.
if (generation == 3)
  fixed_version = "1.65";
else if (generation == 4)
  fixed_version = "1.32";
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "iLO " + generation, install_url, version);

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) >= 0) audit(AUDIT_WEB_APP_NOT_AFFECTED, "iLO " + generation, install_url, version);

set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
if (report_verbosity > 0)
{
  report =
    '\n  URL              : ' + install_url +
    '\n  Generation       : ' + generation +
    '\n  Firmware version : ' + version +
    '\n  Fixed version    : ' + fixed_version +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
