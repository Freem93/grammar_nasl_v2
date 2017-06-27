#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69554);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/21 22:04:46 $");

  script_cve_id("CVE-2013-2338");
  script_bugtraq_id(60480);
  script_osvdb_id(94192);

  script_name(english:"iLO 3 < 1.57 / iLO 4 < 1.22 Unspecified Arbitrary Code Execution");
  script_summary(english:"Checks version of HP Integrated Lights-Out (iLO) and whether SSO is enabled.");

  script_set_attribute(attribute:"synopsis", value:
"The remote HP Integrated Lights-Out (iLO) server's web interface is
affected by a remote code execution vulnerability.") ;
  script_set_attribute(attribute:"description", value:
"According to its version number and single sign-on settings, the
remote HP Integrated Lights-Out (iLO) server is affected by an
arbitrary code execution vulnerability in its web interface.");
  # https://h20565.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c03787836-3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?617d5f70");
  script_set_attribute(attribute:"solution", value:
"For HP Integrated Lights-Out (iLO) 3, disable single sign-on or
upgrade firmware to 1.57 or later. For iLO 4, disable single sign-on
or upgrade firmware to 1.22 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:integrated_lights-out_3_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:integrated_lights-out_4_firmware");
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

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

# Each generation has its own series of firmware version numbers.
generation = get_kb_item_or_exit("ilo/generation");

# The version is tied to the firmware and not specific to the web interface.
version = get_kb_item_or_exit("ilo/firmware");

port = get_http_port(default:80, embedded:TRUE);

install = get_install_from_kb(
  appname      : "ilo",
  port         : port,
  exit_on_fail : TRUE
);
install_url = build_url(port:port, qs:install["dir"]);

# The vulnerability exists in the single sign-on feature.
get_kb_item_or_exit("www/ilo/" + port + "/sso_enabled");

# Firmware is unique to the generation of iLO.
if (generation == 3)
  fixed_version = "1.57";
else if (generation == 4)
  fixed_version = "1.22";
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "iLO " + generation, install_url, version);

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) >= 0)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "iLO " + generation, install_url, version);

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n URL              : ' + install_url +
    '\n Generation       : ' + generation +
    '\n Firmware version : ' + version +
    '\n Fixed version    : ' + fixed_version +
    '\n';
}

security_hole(port:port, extra:report);
