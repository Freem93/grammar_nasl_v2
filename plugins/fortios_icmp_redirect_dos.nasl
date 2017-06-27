#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89867);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/06 19:37:28 $");

  script_osvdb_id(133821);

  script_name(english:"Fortinet FortiOS 5.2.x < 5.2.6 ICMP Redirect Response DoS");
  script_summary(english:"Checks the version of FortiOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Fortinet FortiOS that is 5.2.x
prior to 5.2.6. It is, therefore, affected by a denial of service
vulnerability due to the processing of ICMP redirect packets before a
session has been created. A remote attacker can exploit this to cause
a kernel panic, resulting in a denial of service condition.");
  # http://docs.fortinet.com/uploaded/files/2861/fortios-v5.2.6-release-notes.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?007d4d75");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version 5.2.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_name = "FortiOS";

version = get_kb_item_or_exit("Host/Fortigate/version");
model = get_kb_item_or_exit("Host/Fortigate/model");

# Check that this is a Fortigate device
if (!preg(string:model, pattern:"fortigate", icase:TRUE))
  audit(AUDIT_HOST_NOT, "a FortiGate device");

# Check for affected models.
if (
  '-1000D' >!< model &&
  '-3950B' >!< model &&
  '-3600C' >!< model &&
  '-500D' >!< model
) audit(AUDIT_OS_NOT, "affected FortiGate model");

if (version =~ "^5\.2($|\.)")
  fix = "5.2.6";
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  report_items = make_array(
    "Model", model,
    "Installed version", version,
    "Fixed version", fix
  );
  order = make_list("Model", "Installed version", "Fixed version");
  report = report_items_str(report_items:report_items, ordered_fields:order);
  security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
