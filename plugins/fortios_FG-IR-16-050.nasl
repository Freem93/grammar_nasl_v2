#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97066);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/02/10 14:51:43 $");

  script_cve_id("CVE-2016-7542");
  script_bugtraq_id(94690);
  script_osvdb_id(148229);

  script_name(english:"Fortinet FortiOS 5.2.x < 5.2.10 / 5.4.1 < 5.4.2 Local Password Hash Disclosure (FG-IR-16-050)");
  script_summary(english:"Checks version of FortiOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a local information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote FortiGate device is running a version of FortiOS that is
5.2.x prior to 5.2.10, or else it is running version 5.4.1. It is,
therefore, affected by a local information disclosure vulnerability
due to a failure to properly protect password hashes stored on the
device. A local attacker can exploit this to obtain password hashes of
other users on the device, allowing the attacker to possibly obtain
user passwords, including the passwords of super-admin users.");
  script_set_attribute(attribute:"see_also", value:"http://fortiguard.com/advisory/FG-IR-16-050");
  script_set_attribute(attribute:"see_also", value:"https://labs.mwrinfosecurity.com/advisories/fortigate-hash/");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=50993");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS 5.2.10 / 5.4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/12/02");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/08");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:fortinet:fortios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "FortiOS";

version = get_kb_item_or_exit("Host/Fortigate/version");
model = get_kb_item_or_exit("Host/Fortigate/model");

# Make sure device is FortiGate
if (!preg(string:model, pattern:"fortigate", icase:TRUE)) audit(AUDIT_HOST_NOT, "a FortiGate");

if (version =~ "^5\.2\.") fix = "5.2.10";
else if (version == "5.4.1") fix = "5.4.2";
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  order = make_list("Model", "Installed version", "Fixed version");
  report = make_array(
    order[0], model,
    order[1], version,
    order[2], fix
  );
  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(severity:SECURITY_NOTE, extra:report, port:0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
