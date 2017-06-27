#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92412);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/17 21:12:11 $");

  script_cve_id("CVE-2015-0235");
  script_bugtraq_id(72325);
  script_osvdb_id(117579);
  script_xref(name:"CISCO-BUG-ID", value:"CSCus71708");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus68770");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus69648");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus68591");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus68892");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150128-ghost");
  script_xref(name:"CERT", value:"967332");

  script_name(english:"Cisco NX-OS GNU C Library (glibc) Buffer Overflow (GHOST)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco NX-OS software running on the remote device is
affected by a remote code execution vulnerability known as GHOST. A
heap-based buffer overflow condition exists in the GNU C Library
(glibc) due to improper validation of user-supplied input to the glibc
functions __nss_hostname_digits_dots(), gethostbyname(), and
gethostbyname2(). An unauthenticated, remote attacker can exploit this
to cause a buffer overflow, resulting in a denial of service condition
or the execution of arbitrary code.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150128-ghost
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf670adc");
  # https://www.qualys.com/research/security-advisories/GHOST-CVE-2015-0235.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7a6ddbd");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the vendor
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim GHOST (glibc gethostbyname) Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Device","Host/Cisco/NX-OS/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

device = get_kb_item_or_exit("Host/Cisco/NX-OS/Device");
version = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");
model = get_kb_item_or_exit("Host/Cisco/NX-OS/Model");

if (device != 'Nexus') audit(AUDIT_HOST_NOT, 'a Cisco Nexus device');

bug = NULL;
fix = NULL;
vuln = FALSE;
n7k = FALSE; # Used to distinguish Nexus 7000 Series models in version comparison

# Cisco Nexus 1000V
if (model =~ "^1000[vV]$")
{
  bug = "CSCus71708";
  fix = "5.2(1)SV3(1.4)";
}
# Cisco Nexus 3000
else if (model =~ "^3[0-9][0-9][0-9]([^0-9]|$)")
{
  bug = "CSCus68770";
  if (version =~ "^6\.0\(2\)A")
    fix = "6.0(2)A4(3.41)";
  else if (version =~ "^6\.0\(2\)U")
    fix = "6.0(2)U4(3.41)";
}
# Cisco Nexus 4000
else if (model =~ "^4[0-9][0-9][0-9]([^0-9]|$)" && version =~ "^4\.1([^0-9])")
{
  bug = "CSCus69648";
  fix = "4.1(2)E1(1o)";
}
# Cisco Nexus 5000 and Cisco Nexus 2000
else if (model =~ "^5[0-9][0-9][0-9]([^0-9]|$)" || model =~ "^2[0-9][0-9][0-9]([^0-9]|$)")
{
  bug = "CSCus68591";
  if (version =~ "^5\.") fix = "5.2(1).N1(9)";
  else if (version =~ "^6\.") fix = "6.0(2).N2(7)";
  else if (version =~ "^7\.0\(") fix = "7.0(6).N1(1)";
  else if (version =~ "^7\.1\(") fix = "7.1(1)N1(1)";
  else fix = NULL;
}
# Cisco Nexus 7000
else if (model =~ "^7[0-9][0-9][0-9]([^0-9]|$)")
{
  n7k = TRUE;
  bug = "CSCus68892";
  fix = "6.2(12)";
  if (
    # All versions in releases 4 and 5 affected
    version =~ "^[45]\." ||
    # All versions in 6.0 and 6.1 affected
    version =~ "^6\.[0-1]([^0-9]|$)" ||
    # Versions 6.2 < 6.2(12) affected
    version =~ "^6\.2$" || version =~ "^6\.2\(([0-9]|1[01])\)"
  ) vuln = TRUE;
}
else audit(AUDIT_HOST_NOT, "an affected Cisco Nexus model");

if (!n7k && !isnull(fix) && cisco_gen_ver_compare(a:version, b:fix) < 0) vuln = TRUE;

if (vuln)
{
  report =
    '\n  Cisco bug ID      : ' + bug +
    '\n  Installed release : ' + version +
    '\n  Fixed release     : ' + fix +
    '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco NX-OS software", version);
