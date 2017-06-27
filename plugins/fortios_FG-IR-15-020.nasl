#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85910);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/14 13:50:03 $");

  script_osvdb_id(125578);

  script_name(english:"Fortinet FortiOS 5.2.3 ZebOS Shell Remote Command Execution (FG-IR-15-020)");
  script_summary(english:"Checks the version of FortiOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote command execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Fortinet FortiOS 5.2.3. It is, therefore,
affected by a remote command execution vulnerability that allows an
unauthenticated, remote attacker to execute arbitrary commands via the
internal ZebOS shell on the high availability (HA) dedicated
management interface.");
  script_set_attribute(attribute:"see_also", value:"http://www.fortiguard.com/advisory/FG-IR-15-020");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS 5.2.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "FortiOS";
model = get_kb_item_or_exit("Host/Fortigate/model");

# This is for HA mode only, and is not enabled by default.
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

# Make sure device is FortiGate
if (!preg(string:model, pattern:"fortigate", icase:TRUE))
  audit(AUDIT_HOST_NOT, "a FortiGate");

version = get_kb_item_or_exit("Host/Fortigate/version");

# Only 5.2.3 is affected
if (version == "5.2.3")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Model             : ' + model +
      '\n  Installed version : ' + version +
      '\n  Fixed version     :  5.2.4' +
      '\n';
    security_hole(extra:report, port:0);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
