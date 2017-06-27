#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20130424-fmdm.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(66699);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/10/18 00:11:10 $");

  script_cve_id("CVE-2013-1192");
  script_bugtraq_id(59449);
  script_osvdb_id(92760);
  script_xref(name:"CISCO-BUG-ID", value:"CSCty17417");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130424-fmdm");

  script_name(english:"Cisco Device Manager Command Execution Vulnerability (cisco-sa-20130424-fmdm)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"Cisco Device Manager contains a vulnerability that could allow an
unauthenticated, remote attacker to execute arbitrary commands on a
client host with the privileges of the user. This vulnerability
affects Cisco Device Manager for the Cisco MDS 9000 Family and Cisco
Nexus 5000 Series Switches when it is installed or launched via the
Java Network Launch Protocol (JNLP) on a host running Microsoft
Windows. Cisco Device Manager installed or launched from Cisco Prime
Data Center Network Manager (DCNM) or Cisco Fabric Manager is not
affected. This vulnerability can only be exploited if the JNLP file is
executed on systems running Microsoft Windows. The vulnerability
affects the confidentiality, integrity, and availability of the client
host performing the installation or execution of Cisco Device Manager
via JNLP file. There is no impact on the Cisco MDS 9000 Family or
Cisco Nexus 5000 Series Switches. Cisco has released free software
updates that address this vulnerability in the Cisco Device Manager
for Cisco MDS 9000 Family Switches. Cisco Nexus 5000 Series Switches
have discontinued the support of the Cisco Device Manager installation
via JNLP and updates are not available. Workarounds that mitigate this
vulnerability are available.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130424-fmdm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?322126c8");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130424-fmdm.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/31");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Model", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

device = get_kb_item_or_exit("Host/Cisco/NX-OS/Device");
model = get_kb_item_or_exit("Host/Cisco/NX-OS/Model");
version = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");

if (model !~ '^[59][0-9][0-9][0-9]([^0-9]|$)') audit(AUDIT_HOST_NOT, "affected");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

flag = 0;

# Nexus 5000 Series Devices Affected.
if (device == 'Nexus' && model =~ '^5[0-9][0-9][0-9]([^0-9]|$)')
{
  if (version == '4.0(0)N1(1a)') flag++;
  if (version == '4.0(0)N1(2)') flag++;
  if (version == '4.0(0)N1(2a)') flag++;
  if (version == '4.0(1a)N1(1)') flag++;
  if (version == '4.0(1a)N1(1a)') flag++;
  if (version == '4.0(1a)N2(1)') flag++;
  if (version == '4.0(1a)N2(1a)') flag++;
  if (version == '4.1(3)N1(1)') flag++;
  if (version == '4.1(3)N1(1a)') flag++;
  if (version == '4.1(3)N2(1)') flag++;
  if (version == '4.1(3)N2(1a)') flag++;
  if (version == '4.2(1)N1(1)') flag++;
  if (version == '4.2(1)N2(1)') flag++;
  if (version == '4.2(1)N2(1a)') flag++;
  if (version == '5.0(2)N1(1)') flag++;
  if (version == '5.0(2)N2(1)') flag++;
  if (version == '5.0(2)N2(1a)') flag++;
  if (version == '5.0(3)N1(1c)') flag++;
  if (version == '5.0(3)N2(1)') flag++;
  if (version == '5.0(3)N2(2)') flag++;
  if (version == '5.0(3)N2(2a)') flag++;
  if (version == '5.0(3)N2(2b)') flag++;
  if (version == '5.1(3)N1(1)') flag++;
  if (version == '5.1(3)N1(1a)') flag++;
  if (version == '5.1(3)N2(1)') flag++;
  if (version == '5.1(3)N2(1a)') flag++;
  if (version == '5.1(3)N2(1b)') flag++;
  if (version == '5.1(3)N2(1c)') flag++;
  if (version == '5.2(1)N1(1)') flag++;
  if (version == '5.2(1)N1(1a)') flag++;
  if (version == '5.2(1)N1(1b)') flag++;
  if (version == '5.2(1)N1(2)') flag++;
  if (version == '5.2(1)N1(2a)') flag++;
  if (version == '5.2(1)N1(3)') flag++;
  if (version == '5.2(1)N1(4)') flag++;
}

# MDS 9000 devices before 5.2(8) affected.
if (device == 'MDS' && model =~ '^9[0-9][0-9][0-9]([^0-9]|$)]')
{
  if (
    version =~ "^4\." ||
    version =~ "^5\.0\(" ||
    version =~ "^5\.2\([0-7][a-z]?\)"
  ) flag++;
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Model             : ' + device + ' ' + model +
      '\n  Installed version : ' + version +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
