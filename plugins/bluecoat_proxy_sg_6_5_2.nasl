#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70302);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/05/22 13:36:28 $");

  script_cve_id("CVE-2013-5959");
  script_bugtraq_id(62647);
  script_osvdb_id(97767);

  script_name(english:"Blue Coat ProxySG Recursive HTTP Pipeline Pre-Fetch Remote DoS");
  script_summary(english:"Checks the Blue Coat ProxySG SGOS version");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is potentially affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Security Gateway OS
(SGOS) version installed on the remote Blue Coat ProxySG device is
potentially affected by a denial of service vulnerability caused by a
large amount of HTTP RW pipeline pre-fetch requests.

Note that only devices with forward or reverse mode for HTTP traffic
enabled are affected.");
  script_set_attribute(attribute:"see_also", value:"https://bto.bluecoat.com/security-advisory/sa75");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SGOS version 5.4.12.9 / 5.5.11.5 / 6.2.14.1 / 6.3.6.2 /
6.4.5.1 / 6.5.2.0 or later. Alternatively, apply the workaround
referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:bluecoat:proxysg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:bluecoat:proxysgos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:bluecoat:sgos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Firewalls");

  script_dependencies("bluecoat_proxy_sg_version.nasl");
  script_require_keys("Host/BlueCoat/ProxySG/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

version    = get_kb_item_or_exit("Host/BlueCoat/ProxySG/Version");
ui_version = get_kb_item("Host/BlueCoat/ProxySG/UI_Version");

fix    = NULL;
vuln   = FALSE;

if      (version =~ "^5\.4([^0-9]|$)") fix = '5.4.12.9';
else if (version =~ "^5\.5([^0-9]|$)") fix = '5.5.11.5';
else if (version =~ "^6\.2([^0-9]|$)") fix = '6.2.14.1';
else if (version =~ "^6\.3([^0-9]|$)") fix = '6.3.6.2';
else if (version =~ "^6\.4([^0-9]|$)") fix = '6.4.5.1';
else if (version =~ "^6\.5([^0-9]|$)") fix = '6.5.2.0';

if (!isnull(fix) && ver_compare(ver:version, fix:fix, strict:FALSE) == -1) vuln = TRUE;

# 6.1. 5.3 and earlier have no fix
if (isnull(fix) && version =~ "^([0-4]\.[0-9]+|5\.[0-3]|6\.1)([^0-9]|$)")
{
  fix  = "Refer to the vendor.";
  vuln = TRUE;
}

if (!vuln) audit(AUDIT_INST_VER_NOT_VULN, 'Blue Coat ProxySG', version);

if (report_verbosity > 0)
{
  report_ver = NULL;
  report_fix = NULL;

  # Select format for output
  if (isnull(ui_version))
  {
    report_ver = version;
    report_fix = fix;
  }
  else
  {
    report_ver = ui_version;
    report_fix = fix + " Build 0";
  }

  report =
    '\n  Installed version : ' + report_ver +
    '\n  Fixed version     : ' + report_fix +
    '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);
