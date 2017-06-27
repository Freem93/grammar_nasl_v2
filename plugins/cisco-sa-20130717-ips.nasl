#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69103);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/03/21 19:41:17 $");

  script_cve_id(
    "CVE-2013-1218",
    "CVE-2013-1243",
    "CVE-2013-3410",
    "CVE-2013-3411"
  );
  script_bugtraq_id(61294, 61299, 61300, 61301);
  script_osvdb_id(95393, 95394, 95395, 95396);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtx18596");
  script_xref(name:"CISCO-BUG-ID", value:"CSCue51272");
  script_xref(name:"CISCO-BUG-ID", value:"CSCua61977");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuh27460");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130717-ips");

  script_name(english:"Multiple Vulnerabilities in Cisco Intrusion Prevention System Software (cisco-sa-20130717-ips)");
  script_summary(english:"Checks IPS version");

  script_set_attribute(attribute:"synopsis", value:"The remote security appliance is missing a vendor-supplied patch.");
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version, the version of the Cisco
Intrusion Prevention System Software running on the remote host has the
following vulnerabilities :

  - The IP stack in Cisco IPS Software could allow remote
    attackers to cause a denial of service (DoS) condition
    via malformed IPv4 packets. (CVE-2013-1243)

  - Cisco IPS Software could allow remote attackers to cause
    a DoS condition via fragmented IPv4 or IPv6 packets.
    (CVE-2013-1218)

  - Cisco IPS Software on some IPS NME devices could allow
    remote attackers to cause a DoS condition via malformed
    IPv4 packets that trigger incorrect memory allocation.
    (CVE-2013-3410)

  - The IDSM-2 drivers in Cisco IPS Software on Cisco
    Catalyst 6500 devices with an IDSM-2 module could allow
    remote attackers to cause a DoS condition via malformed
    IPv4 TCP packets. (CVE-2013-3411)"
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130717-ips
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ab63f245");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant update referenced in Cisco Security Advisory
cisco-sa-20130717-ips."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:intrusion_prevention_system");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("cisco_ips_version.nasl");
  script_require_keys("Host/Cisco/IPS/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Cisco/IPS/Version');
model = get_kb_item_or_exit('Host/Cisco/IPS/Model');
display_fix = "";

if (model =~ "43\d\d")
{
  if ((ver == "7.1(3)E4") || (ver == "7.1(4)E4")) display_fix = "7.1(7)E4";
}
else if (model =~ "45\d\d")
{
  if (ver == "7.1(4)E4") display_fix = "7.1(7)E4";
}
else if (model =~ "ASA.*55\d\d")
{
  if ( (ver == "7.1(1)E4") || (ver == "7.1(2)E4") ||
       (ver == "7.1(3)E4") || (ver == "7.1(4)E4") ||
       (ver == "7.1(5)E4") || (ver == "7.1(6)E4") ||
       (ver == "7.1(7)E4")) display_fix = "7.1(7p1)E4";
}
else if (model =~ "NME")
{
  if (ver_compare(ver:ver, fix:"7.0(9)E4", strict:FALSE) < 0)
    display_fix = "7.0(9)E4";
}
else if (model =~ "IDSM-2")
{
  display_fix = "no fixed version currently available";
}

if (display_fix == "")
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco IPS', ver);

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + display_fix + '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);

