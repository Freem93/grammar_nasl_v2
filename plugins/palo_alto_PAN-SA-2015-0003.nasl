#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83816);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/03 20:51:50 $");

  script_bugtraq_id(74681);
  script_osvdb_id(122213);

  script_name(english:"Palo Alto Networks PAN-OS < 5.0.16 / 6.0.x < 6.0.9 / 6.1.x < 6.1.3 XSS");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Palo Alto Networks PAN-OS
prior to 5.0.16 / 6.0.9 / 6.1.3. It is, therefore, affected by a
cross-site vulnerability in the management interface due to improper
validation of user-supplied input. A remote attacker can exploit this
vulnerability by convincing an authenticated administrator to use a
specially crafted request, resulting in execution of arbitrary code in
the context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/30");
  script_set_attribute(attribute:"solution", value:"Upgrade to PAN-OS 5.0.16 / 6.0.9 / 6.1.13");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Palo Alto Local Security Checks");

  script_dependencies("palo_alto_version.nbin");
  script_require_keys("Host/Palo_Alto/Firewall/Version", "Host/Palo_Alto/Firewall/Full_Version");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Palo Alto Networks PAN-OS";
version = get_kb_item_or_exit("Host/Palo_Alto/Firewall/Version");
full_version = get_kb_item_or_exit("Host/Palo_Alto/Firewall/Full_Version");
fix = NULL;

# Ensure sufficient granularity.
if (
  version =~ "^5(\.0)?$" ||
  version =~ "^6(\.[01])?$"
) audit(AUDIT_VER_NOT_GRANULAR, app_name, full_version);

if (version =~ "^6\.1\.")
{
  fix = "6.1.3";
}
else if (version =~ "^6\.0\.")
{
  fix = "6.0.9";
}
else if (
  version =~ "^[0-4]($|[^0-9])" ||
  version =~ "^5\.0\."
)
{
  fix = "5.0.16";
}
else
  audit(AUDIT_NOT_INST, app_name + " 0.x-4.x / 5.0.x / 6.0.x / 6.1.x");

# Compare version to fix and report as needed.
if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  set_kb_item(name:'www/0/XSS', value: TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + full_version +
      '\n  Fixed versions    : ' + fix +
      '\n';
    security_warning(extra:report, port:0);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, full_version);
