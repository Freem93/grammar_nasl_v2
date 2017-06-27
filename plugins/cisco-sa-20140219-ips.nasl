#TRUSTED 40b3ad5c63be9217450c04f29f312ee77d3bbdf108074d8bfdd212d0ff96f9ca5d1a2545e68a04400e6fc078ed034ef3384955defc01a8600c31448b220e934dc62ddbab406359bf83f4f35a23f917e05dd9c5112edf404db55d97d389626a8ec318fdeb4ab2ea25b5fd85d7dd9ed78985c30bc78faa62fc6b18f555b8b95ec8faf852001ab2d22bb65fe5c4d88417542b817d944f61b29f2cd7919d9668157453006a18863b3d676f615a27ebfc953ce55e2f0edd8830daa6f642c73e2fe9277ebc0a4fd10a747af7bce417c812833bb1a8ae8f5d1e4a3756d408318611fa88d4b507c0e671c355ffedc3babab8cb491a3d2fa6ef710093c4c41d1d4564a60051e841a83b6682842a599a74f87b5922fba45e58a9a594fe3584bc76dfba7b84ff364d651981c458f2b50058f292aebdab76057d7bb0f9619c32ed1f2506a3d044263f34344ba20ced5a93a5096da72f59ede5a9ca6168401000e05e1fec6ed1cd2a616e96aaf8b8236bc3417c0f60f51d7c8169478e5df43ad9d93a2d44a7018cc4cf54b20a9245a11829422996e3604da2dedc44ae0627bfbac428a22645fdced5bad09f7f5c8ce782f6a271fe3067ed5dd878cc71e27add400ad3ede71418131be2cb9222def4e8b57e796270d050e6621d379aa77f4adc43bc04011f799382bb7f1c76b1aa979f0e4025ea638ea18a7424bc55685fbd326a62c7d4ce06f3
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72705);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/12/19");

  script_cve_id("CVE-2014-0718", "CVE-2014-0719", "CVE-2014-0720");
  script_bugtraq_id(65665, 65667, 65669);
  script_osvdb_id(103469, 103470, 103471);
  script_xref(name:"CISCO-BUG-ID", value:"CSCui67394");
  script_xref(name:"IAVA", value:"2014-A-0032");
  script_xref(name:"CISCO-BUG-ID", value:"CSCui91266");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuh94944");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140219-ips");

  script_name(english:"Multiple Vulnerabilities in Cisco Intrusion Prevention System Software (cisco-sa-20140219-ips)");
  script_summary(english:"Checks the IPS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote security appliance is missing a vendor-supplied patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of the Cisco
Intrusion Prevention System software running on the remote is affected
by the following denial of service vulnerabilities :

  - The Analysis Engine can become unresponsive due to
    improper handling of fragmented packets processed
    through the device. The device is only affected when
    the 'produce-verbose-alert' action is enabled.
    (CVE-2014-0718)

  - The MainApp can become unresponsive due to improper
    handling of malformed TCP packets sent to the
    management interface. Other critical tasks such as
    alert notification, event store management, sensor
    authentication, and the Analysis Engine can become
    unresponsive as well. (CVE-2014-0719)

  - The Analysis Engine can become unresponsive due to
    improper handling of jumbo frames sent at a high rate.
    (CVE-2014-0720)

An unauthenticated, remote attacker can exploit these issues to cause
a denial of service."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140219-ips
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?14f261a3");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant update referenced in Cisco Security Advisory
cisco-sa-20140219-ips."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:intrusion_prevention_system");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("cisco_ips_version.nasl");
  script_require_keys("Host/Cisco/IPS/Version", "Host/Cisco/IPS/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit('Host/Cisco/IPS/Version');
model = get_kb_item_or_exit('Host/Cisco/IPS/Model');
model_ver = eregmatch(pattern:"[^0-9]([0-9]{4,})[^0-9]", string:model);
model_ver = model_ver[1];

flag = 0;
report = '\n  Model: ' + model + '\n';
fixed_ver = "";

# #################################################
# CSCui91266
# #################################################
cbi = "CSCui91266";
temp_flag = 0;

if (
  model_ver =~ "^42\d\d$" || model_ver =~ "^43\d\d$" ||
  model_ver =~ "^45\d\d$" || model =~ "ASA.*SS(M|P)"
)
{
  if (ver =~ "^7\.1\([4-7](p\d)?\)E4")
  {
    temp_flag++;
    fixed_ver = "7.1(8)E4";

    # Check if the 'produce-verbose-alert' option is enabled
    if (get_kb_item("Host/local_checks_enabled"))
    {
      temp_flag = 0;
      buf = cisco_command_kb_item("Host/Cisco/Config/show_configuration", "show configuration");
      if (check_cisco_result(buf))
        if (preg(multiline:TRUE, pattern:"produce-verbose-alert", string:buf)) temp_flag++;
    }
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# #################################################
# CSCui67394
# #################################################
cbi = "CSCui67394";
temp_flag = 0;

if (model =~ "ASA.*SS(M|P)")
{
  if (
    ver =~ "^6\." ||
    ver =~ "^7\.0\(" ||
    ver =~ "^7\.1\([1-7](p\d)?\)E4" ||
    ver =~ "^7\.1\(8(p1)?\)E4")
  {
    temp_flag++;
    fixed_ver = "7.1(8p2)E4";
  }

  else if (ver =~ "^7\.2\(1(p[12])?\)E4")
  {
    temp_flag++;
    fixed_ver = "7.2(2)E4";
  }
}
# Cisco ASA 5505 Advanced Inspection and Prevention Security Services Card (AIP SSC)
else if (model =~ "ASA.*SSC")
{
  fixed_ver = "Refer to the Cisco advisory for more information.";
  temp_flag++;
}


if (temp_flag)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# #################################################
# CSCuh94944
# #################################################
cbi = "CSCuh94944";
temp_flag = 0;

if (model_ver =~ "^45\d\d$")
{
  if (ver =~ "^7\.1\([1-7](p\d)?\)E4")
  {
    temp_flag++;
    fixed_ver = "7.1(8)E4";
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# Reporting
if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:report);
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Cisco IPS', ver + ' on model ' + model);
