#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70411);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/04/01 11:53:04 $");

  script_cve_id("CVE-2013-3589");
  script_bugtraq_id(62598);
  script_osvdb_id(97623);
  script_xref(name:"CERT", value:"920038");

  script_name(english:"Dell iDRAC6 / iDRAC7 Login Page 'ErrorMsg' Parameter XSS");
  script_summary(english:"Checks version of iDRAC");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Dell Remote Access Controller (iDRAC6 / iDRAC7) is affected
by a cross-site scripting vulnerability in the login page due to
improper sanitization of user-supplied input to the 'ErrorMsg'
parameter. An attacker can exploit this to inject arbitrary HTML and
script code into a user's browser to be executed within the security
context of the affected site.

Note that iDRAC6 'modular' (blades) are not affected by this issue and
no updates are required.");
  # http://downloads.dell.com/Manuals/all-products/esuprt_software/esuprt_remote_ent_sys_mgmt/esuprt_rmte_ent_sys_rmte_access_cntrllr/integrated-dell-remote-access-cntrllr-7-v1.40.40_FAQ_en-us.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e485807");
  script_set_attribute(attribute:"solution", value:"Upgrade to firmware version 1.96 (iDRAC6) / 1.46.45 (iDRAC7) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:remote_access_card");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:dell:idrac6_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:dell:idrac7_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("drac_detect.nasl");
  script_require_keys("installed_sw/iDRAC");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "iDRAC";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:443, embedded:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
firmware = install['Firmware Version'];
install_url = build_url(port:port, qs:dir);

# Affects DRAC versions 6 and 7
if (version !~ "^(6|7)")
  audit(AUDIT_WRONG_WEB_SERVER, port, "iDRAC6 / iDRAC7 and therefore is not affected");

if (firmware == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_WEB_SERVER_VER, "iDRAC", port);

vuln = FALSE;
if (version == "6")
{
  fix = "1.96";
  if (ver_compare(ver:firmware, fix:fix, strict:FALSE) == -1) vuln = TRUE;
}
if (version == "7")
{
  fix = "1.46.45";
  if (ver_compare(ver:firmware, fix:fix, strict:FALSE) == -1) vuln = TRUE;
}

if (vuln)
{
  items = make_array(
    "URL", install_url,
    "iDRAC version", version,
    "Firmware version", firmware,
    "Fixed version", fix
  );
  order = make_list("URL","iDRAC version","Firmware version","Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING, xss:TRUE);
  exit(0);
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app + version, install_url, firmware);
