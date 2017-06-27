#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78693);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/04/25 20:29:05 $");

  script_cve_id(
    "CVE-2014-6271",
    "CVE-2014-6277",
    "CVE-2014-6278",
    "CVE-2014-7169",
    "CVE-2014-7186",
    "CVE-2014-7187"
  );
  script_bugtraq_id(
    70103,
    70137,
    70152,
    70154,
    70165,
    70166
  );
  script_osvdb_id(
    112004,
    112096,
    112097,
    112158,
    112169
  );
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"CISCO-BUG-ID", value:"CSCur01099");
  script_xref(name:"CISCO-BUG-ID", value:"CSCur04438");
  script_xref(name:"CISCO-BUG-ID", value:"CSCur04510");
  script_xref(name:"CISCO-BUG-ID", value:"CSCur05529");
  script_xref(name:"CISCO-BUG-ID", value:"CSCur05610");
  script_xref(name:"CISCO-BUG-ID", value:"CSCur05017");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuq98748");
  script_xref(name:"CISCO-BUG-ID", value:"CSCur02102");
  script_xref(name:"CISCO-BUG-ID", value:"CSCur02700");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140926-bash");
  script_xref(name:"CERT", value:"252743");
  script_xref(name:"EDB-ID", value:"34765");
  script_xref(name:"EDB-ID", value:"34766");
  script_xref(name:"EDB-ID", value:"34777");

  script_name(english:"Cisco NX-OS GNU Bash Environment Variable Command Injection Vulnerability (cisco-sa-20140926-bash) (Shellshock)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is running a version of NX-OS that is affected by
Shellshock.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote NX-OS device is
affected by a command injection vulnerability in GNU Bash known as
Shellshock, which is due to the processing of trailing strings after
function definitions in the values of environment variables. This
allows a remote attacker to execute arbitrary code via environment
variable manipulation depending on the configuration of the system.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140926-bash
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7269978d");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q3/650");
  script_set_attribute(attribute:"see_also", value:"https://www.invisiblethreat.ca/post/shellshock/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the suggested fixed version referred to in the relevant
Cisco bug ID. Note that some fixed versions have not been released
yet. Please contact the vendor for details.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CUPS Filter Bash Environment Variable Code Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

device = get_kb_item_or_exit("Host/Cisco/NX-OS/Device");
model = get_kb_item_or_exit("Host/Cisco/NX-OS/Model");
version = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");

fixed = '';
bug_ID = '';

# MDS 9000 NX-OS prior to 5.0(8a) / 5.2(8e) / 6.2(9a)
if (device == 'MDS' && model =~ "^9[0-9][0-9][0-9]([^0-9]|$)")
{
  bug_ID = 'CSCur01099';

  if (
    version =~ "^[2-4]\." ||
    version =~ "^5\.0\([0-7][A-Za-z]?\)" ||
    version =~ "^5\.0\(8\)"
  ) fixed = '5.0(8a)';

  if (
    version =~ "^5\.2\([0-7][A-Za-z]?\)" ||
    version =~ "^5\.2\(8[A-Da-d]?\)"
  ) fixed = '5.2(8e)';

  if (
    version =~ "^6\.2\([0-8][A-Za-z]?\)" ||
    version =~ "^6\.2\(9\)"
  ) fixed = '6.2(9a)';
}

# Nexus 1000V, only valid known version affected is 5.2(1)SV3(1.1)
if (device == 'Nexus' && model =~ "^1[0-9][0-9][0-9][Vv]$")
{
  bug_ID = 'CSCur04438';

  if (
    version =~ "^5\.2\(1\)SV3\(1\.1\)"
  ) fixed = 'Contact Vendor';
}

# Nexus 1010, versions affected are 4.2(1)SP1(6.2), and 9.2(1)SP1(4.8)
if (device == 'Nexus' && model =~ "^101[0-9]([^0-9]|$)")
{
  bug_ID = 'CSCur04510';

  if (
    version =~ "^4\.2\(1\)SP1\(6\.2\)" ||
    version =~ "^9\.2\(1\)SP1\(4\.8\)"
  ) fixed = '5.2(1)SP1(7.2)';
}

# Nexus 3000 fixed versions 6.0(2)U2(6) / 6.0(2)U3(4) / 6.0(2)U4(2) / 6.0(2)U5(1)
# Nexus 3500 fixed versions 6.0(2)A3(4) / 6.0(2)A4(2) / 6.0(2)A5(1)
# The A5 and U5 versions appear to be the first release for those branches.
if (device == 'Nexus' && model =~ "^3[0-9][0-9][0-9]([^0-9]|$)")
{
  bug_ID = 'CSCur05529';

  if (
    version =~ "^5\.0\(3\)U" ||
    version =~ "^6\.0\(2\)U1\(" ||
    version =~ "^6\.0\(2\)U2\([0-5]\)"
  ) fixed = "6.0(2)U2(6)";

  if (
    version =~ "^6\.0\(2\)U3\([0-3]\)"
  ) fixed = "6.0(2)U3(4)";

  if (
    version =~ "^6\.0\(2\)U4\([01]\)"
  ) fixed = "6.0(2)U4(2) / 6.0(2)U5(1)";

  if (
    version =~ "^5\.0\(3\)A" ||
    version =~ "^6\.0\(2\)A[12]\(" ||
    version =~ "^6\.0\(2\)A3\([0-3]\)"
  ) fixed = "6.0(2)A3(4)";

  if (
    version =~ "^6\.0\(2\)A4\(1\)"
  ) fixed = "6.0(2)A4(2) / 6.0(2)A5(1)";
}

# Nexus 4000 4.1(2)E1(1) known affected release
if (device == 'Nexus' && model =~ "^4[0-9][0-9][0-9]([^0-9]|$)")
{
  bug_ID = 'CSCur05610';

  if (
    version =~ "^4\.1\(2\)E1\(1\)"
  ) fixed = "Contact Vendor";
}

# Nexus 5000 / 6000, 5.2(1)N1(8a) / 6.0(2)N2(5) / 7.0(3)N1(0.125)
#                    7.0(4)N1(1) / 7.1(0)N1(0.349)
# Known affected releases
if (device == 'Nexus' && model =~ "^56[0-5][0-9][0-9]([^0-9]|$)")
{
  bug_ID = 'CSCur05017';

  if (
    version =~ "^5\.2\(1\)N1\(8a\)" ||
    version =~ "^6\.0\(2\)N2\(5\)" ||
    version =~ "^7\.0\(3\)N1\(0\.125\)" ||
    version =~ "^7\.0\(4\)N1\(1\)" ||
    version =~ "^7\.1\(0\)N1\(0\.349\)"
  ) fixed = "Contact Vendor";
}

# Nexus 7000 fixed in 5.2(9a) / 6.1(5a) / 6.2(8b) / 6.2(10) and above
if (device == 'Nexus' && model =~ "^7[0-6][0-9][0-9]([^0-9]|$)")
{
  bug_ID = 'CSCuq98748';

  if (
    version =~ "^4\." ||
    version =~ "^5\.[01]\(" ||
    version =~ "^5\.2\([0-9]\)"
  ) fixed = "5.2(9a)";

  if (
    version =~ "^6\.0\(" ||
    version =~ "^6\.1\([0-4][Aa]?\)" ||
    version =~ "^6\.1\(5\)"
  ) fixed = "6.1(5a)";

  if (
    version =~ "^6\.2\([0-8][Aa]?\)"
  ) fixed = "6.2(8b) / 6.2(10)";
}

# Nexus 9000 known affected 6.1(2)I2(2b) / 7.2(0.1)VB(0.1)
# Nexus 9000 ACI version prior to 11.0(1d) affected
if (device == 'Nexus' && model =~ "^9[0-6][0-9][0-9]([^0-9]|$)")
{
  if (
    version =~ "^6\.1\(2\)I2\(2b\)" ||
    version =~ "^7\.2\(0\.1\)VB\(0\.1\)"
  )
  {
    bug_ID = 'CSCur02700';
    fixed = "6.1(2)I3(1)";
  }

  if (
    version =~ "^11\.0\(1[bc]\)"
  )
  {
    bug_ID = 'CSCur02102';
    fixed = "11.0(1d)";
  }
}

if (!empty(fixed) && !empty(bug_ID))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : ' + bug_ID +
      '\n  Model             : ' + device + ' ' + model +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
