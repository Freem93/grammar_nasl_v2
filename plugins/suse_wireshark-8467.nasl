#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(64797);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/03/23 03:06:27 $");

  script_cve_id("CVE-2013-1572", "CVE-2013-1573", "CVE-2013-1574", "CVE-2013-1575", "CVE-2013-1576", "CVE-2013-1577", "CVE-2013-1578", "CVE-2013-1579", "CVE-2013-1580", "CVE-2013-1581", "CVE-2013-1582", "CVE-2013-1583", "CVE-2013-1584", "CVE-2013-1585", "CVE-2013-1586", "CVE-2013-1588", "CVE-2013-1589", "CVE-2013-1590");

  script_name(english:"SuSE 10 Security Update : wireshark (ZYPP Patch Number 8467)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Wireshark has been updated to 1.6.13 which fixes bugs and security
issues :

The following vulnerabilities have been fixed :

  - Infinite and large loops in the Bluetooth HCI, CSN.1,
    DCP-ETSI DOCSIS CM-STAUS, IEEE 802.3 Slow Protocols,
    MPLS, R3, RTPS, SDP, and SIP dissectors wnpa-sec-2013-01
    CVE-2013-1572 / CVE-2013-1573 / CVE-2013-1574 /
    CVE-2013-1575 / CVE-2013-1576 / CVE-2013-1577 /
    CVE-2013-1578 / CVE-2013-1579 / CVE-2013-1580 /
    CVE-2013-1581

  - The CLNP dissector could crash wnpa-sec-2013-02
    CVE-2013-1582

  - The DTN dissector could crash wnpa-sec-2013-03
    CVE-2013-1583 / CVE-2013-1584

  - The MS-MMC dissector (and possibly others) could crash
    wnpa-sec-2013-04 CVE-2013-1585

  - The DTLS dissector could crash wnpa-sec-2013-05
    CVE-2013-1586

  - The DCP-ETSI dissector could corrupt memory
    wnpa-sec-2013-07 CVE-2013-1588: * The Wireshark
    dissection engine could crash wnpa-sec-2013-08
    CVE-2013-1589: * The NTLMSSP dissector could overflow a
    buffer wnpa-sec-2013-09 CVE-2013-1590: Further bug fixes
    and updated protocol support as listed in :

http://www.wireshark.org/docs/relnotes/wireshark-1.6.13.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1572.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1573.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1574.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1575.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1576.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1577.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1578.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1579.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1580.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1581.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1582.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1583.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1584.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1585.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1586.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1588.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1589.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1590.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 8467.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:4, reference:"wireshark-1.6.13-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"wireshark-1.6.13-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"wireshark-devel-1.6.13-0.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else exit(0, "The host is not affected.");
