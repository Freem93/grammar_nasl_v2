#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82663);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/04 14:30:40 $");

  script_cve_id("CVE-2015-0204");
  script_bugtraq_id(71936);
  script_osvdb_id(116794);
  script_xref(name:"CERT", value:"243585");

  script_name(english:"Blue Coat ProxySG 6.5.x / 6.2.x / 5.5 OpenSSL Vulnerability (FREAK)");
  script_summary(english:"Checks the Blue Coat ProxySG SGOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a security feature bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Blue Coat ProxySG device's self-reported SGOS version is
6.5 prior to 6.5.6.2, or version 6.2 prior to 6.2.16.3, or else any
version of 5.5. Therefore, it contains a bundled version of OpenSSL
affected by a security feature bypass vulnerability, known as FREAK
(Factoring attack on RSA-EXPORT Keys), due to the support of weak
EXPORT_RSA cipher suites with keys less than or equal to 512 bits. A
man-in-the-middle attacker may be able to downgrade the SSL/TLS
connection to use EXPORT_RSA cipher suites which can be factored in a
short amount of time, allowing the attacker to intercept and decrypt
the traffic.");
  script_set_attribute(attribute:"see_also", value:"https://bto.bluecoat.com/security-advisory/sa91");
  script_set_attribute(attribute:"see_also", value:"https://www.smacktls.com/#freak");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 6.2.16.3 / 6.5.6.2 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:bluecoat:sgos");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/09");

  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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

if(version !~ "^6\.(5|2)\." && version !~ "^5\.5\.")
  audit(AUDIT_HOST_NOT, "Blue Coat ProxySG 6.5.x / 6.2.x / 5.5.x");

report_fix = NULL;

# Select version for report
if (isnull(ui_version)) report_ver = version;
else report_ver = ui_version;

# For 5.5 suggest latest version
if(version =~ "^(6|5)\.5\." && ver_compare(ver:version, fix:"6.5.6.2", strict:FALSE) == -1)
{
  fix    = '6.5.6.2';
  ui_fix = '6.5.6.2 Build 0';
}
else if(version =~ "^6\.2\." && ver_compare(ver:version,fix:"6.2.16.3",strict:FALSE) == -1)
{
  fix    = '6.2.16.3';
  ui_fix = '6.2.16.3 Build 0';
}
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Blue Coat ProxySG', version);

# Select fixed version for report
if (isnull(ui_version)) report_fix = fix;
else report_fix = ui_fix;

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + report_ver +
    '\n  Fixed version     : ' + report_fix +
    '\n';
  security_warning(port:0, extra:report);
}
else security_warning(0);
exit(0);
