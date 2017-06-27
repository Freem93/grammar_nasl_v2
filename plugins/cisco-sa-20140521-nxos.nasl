#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74241);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/05/16 19:35:38 $");

  script_cve_id(
    "CVE-2013-1191",
    "CVE-2014-2200",
    "CVE-2014-2201",
    "CVE-2014-3261"
  );
  script_bugtraq_id(67571, 67574, 67575, 67578);
  script_osvdb_id(107199, 107200, 107201, 107202);
  script_xref(name:"CISCO-BUG-ID", value:"CSCti11629");
  script_xref(name:"IAVA", value:"2014-A-0077");
  script_xref(name:"CISCO-BUG-ID", value:"CSCug14405");
  script_xref(name:"CISCO-BUG-ID", value:"CSCts56628");
  script_xref(name:"CISCO-BUG-ID", value:"CSCts56632");
  script_xref(name:"CISCO-BUG-ID", value:"CSCts56633");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuf61322");
  script_xref(name:"CISCO-BUG-ID", value:"CSCud88400");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtw98915");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140521-nxos");

  script_name(english:"Cisco NX-OS Multiple Vulnerabilities (cisco-sa-20140521-nxos)");
  script_summary(english:"Checks the NX-OS version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is running a vulnerable version of NX-OS.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote NX-OS device is
reportedly affected by one or more of the following vulnerabilities :

  - A privilege escalation flaw exists on systems with
    multiple virtual device contexts (VDCs) and local
    authentication configured. This could allow a
    remote, authenticated attacker to gain the privileges
    of an administrator in another VDC. Affects Nexus 7000
    series devices. (CVE-2013-1191)

  - A privilege escalation flaw exists on systems with
    multiple virtual device contexts (VDCs) and local
    authentication configured. This could allow a
    remote, authenticated attacker to gain the privileges
    of an administrator in another VDC. Affects Nexus 7000
    series devices. (CVE-2014-2200).

  - A buffer overflow flaw exists with the Smart Call Home
    feature. A remote attacker, with control of a
    configured SMTP server, could execute arbitrary code
    with elevated privileges. (CVE-2014-3261)

  - A denial of service flaw exists with the Message
    Transfer Service (MTS) due to a NULL pointer
    dereference. This could allow a remote attacker to
    trigger a denial of service. Note that Cisco has
    investigated the issue, and has found that no official
    releases are affected. Only pre-release versions of
    NX-OS 6.0 are affected. (CVE-2014-2201)");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=34245");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=34246");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=34247");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=34248");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140521-nxos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5f6099be");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2014/May/122");
  script_set_attribute(attribute:"solution", value:"Upgrade to 4.1(2)E1(1l) / 5.0(3)U2(2) / 5.1(3)N1(1) / 6.1(5) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/30");

  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

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

# Does not affect Nexus 1000v, 1010, 1100, 2000, 5600, 6000, 7700, 9000  series systems
if (
  device != 'Nexus' ||
  model =~ "^[1269][0-9][0-9][0-9]([^0-9]|$)$" ||
  model =~ "^56[0-9][0-9]([^0-9]|$)" ||
  model =~ "^77[0-9][0-9]([^0-9]|$)"
) audit(AUDIT_HOST_NOT, "affected");

fixed = '';

# Nexus 3000 5.0(3)U2(1) and prior affected
if (model =~ "^3[0-9][0-9][0-9]([^0-9]|$)")
{
  if (
    version =~ "^5\.0\(3\)U1\(" ||
    version =~ "^5\.0\(3\)U2\(1\)"
  ) fixed = "5.0(3)U2(2)";
}

# Nexus 4000 4.1(2)E1(1k) and prior affected
if (model =~ "^4[0-9][0-9][0-9]([^0-9]|$)")
{
  if (version =~ "^4\.1\(2\)E1\(1[a-k]?\)") fixed = "4.1(2)E1(1l)";
}

# Nexus 5000 4.X, 5.0.x affected
if (model =~ "^5[0-5][0-9][0-9]([^0-9]|$)")
{
  if (
    version =~ "^4\." ||
    version =~ "^5\.0\("
  ) fixed = "5.1(3)N1(1)";
}

# Nexus 7000 4.x, 5.x, 6.0(x),  6.1(4a) and prior affected
if (model =~ "^7[0-6][0-9][0-9]([^0-9]|$)")
{
  if (
    version =~ "^4\." ||
    version =~ "^5\." ||
    version =~ "^6\.0\(" ||
    version =~ "^6\.1\([0-4]a?\)"
  ) fixed = "6.1(5)";
}

if (!empty(fixed))
{
  if (report_verbosity > 0)
  {
    report =
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
