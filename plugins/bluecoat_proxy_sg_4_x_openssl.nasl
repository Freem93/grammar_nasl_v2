#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76163);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/04/27 19:46:26 $");

  script_cve_id("CVE-2014-0224");
  script_bugtraq_id(67899);
  script_osvdb_id(107729);
  script_xref(name:"CERT", value:"978508");

  script_name(english:"Blue Coat ProxySG 4.x OpenSSL Security Bypass");
  script_summary(english:"Checks the Blue Coat ProxySG SGOS version");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is potentially affected by a security bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Blue Coat ProxySG device's SGOS self-reported version is
4.x and reportedly contains a bundled version of OpenSSL that has
multiple flaws. It is, therefore, potentially affected by an
unspecified error that could allow an attacker to cause usage of weak
keying material, leading to simplified man-in-the-middle attacks.");
  script_set_attribute(attribute:"see_also", value:"https://bto.bluecoat.com/security-advisory/sa80");
  script_set_attribute(attribute:"solution", value:
"Note that ProxySG 4.0.x, 4.1.x, 4.2.x and 4.3.x will not receive a
patch for this issue.

Please contact the vendor for upgrade options.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:bluecoat:sgos");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/20");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"Firewalls");

  script_dependencies("bluecoat_proxy_sg_version.nasl");
  script_require_keys("Host/BlueCoat/ProxySG/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version    = get_kb_item_or_exit("Host/BlueCoat/ProxySG/Version");
ui_version = get_kb_item("Host/BlueCoat/ProxySG/UI_Version");

if (version !~ "^4\.[0-3]\.") audit(AUDIT_HOST_NOT, "Blue Coat ProxySG 4.0.x / 4.1.x / 4.2.x / 4.3.x");

report_fix = NULL;

# Select version for report
if (isnull(ui_version)) report_ver = version;
else report_ver = ui_version;

if (version =~ "^4\.[0-3]\.")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + report_ver +
      '\n  Fixed version     : Please contact the vendor for upgrade options.' +
      '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Blue Coat ProxySG', version);
