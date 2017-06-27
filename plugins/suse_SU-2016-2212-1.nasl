#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2212-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93342);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/27 20:24:09 $");

  script_cve_id("CVE-2016-5350", "CVE-2016-5351", "CVE-2016-5352", "CVE-2016-5353", "CVE-2016-5354", "CVE-2016-5355", "CVE-2016-5356", "CVE-2016-5357", "CVE-2016-5358", "CVE-2016-5359", "CVE-2016-6504", "CVE-2016-6505", "CVE-2016-6506", "CVE-2016-6507", "CVE-2016-6508", "CVE-2016-6509", "CVE-2016-6510", "CVE-2016-6511");
  script_osvdb_id(138537, 139587, 139588, 139589, 139590, 139591, 139592, 139593, 139594, 139595, 142231, 142232, 142233, 142234, 142235, 142236, 142237, 142238);

  script_name(english:"SUSE SLES11 Security Update : wireshark (SUSE-SU-2016:2212-1)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update to wireshark 1.12.13 fixes the following issues :

  - CVE-2016-6504: wireshark: NDS dissector crash
    (bsc#991012)

  - CVE-2016-6505: wireshark: PacketBB dissector could
    divide by zero (bsc#991013)

  - CVE-2016-6506: wireshark: WSP infinite loop (bsc#991015)

  - CVE-2016-6507: wireshark: MMSE infinite loop
    (bsc#991016)

  - CVE-2016-6508: wireshark: RLC long loop (bsc#991017)

  - CVE-2016-6509: wireshark: LDSS dissector crash
    (bsc#991018)

  - CVE-2016-6510: wireshark: RLC dissector crash
    (bsc#991019)

  - CVE-2016-6511: wireshark: OpenFlow long loop (bnc991020)

  - CVE-2016-5350: SPOOLS infinite loop (bsc#983671)

  - CVE-2016-5351: IEEE 802.11 dissector crash (bsc#983671)

  - CVE-2016-5352: IEEE 802.11 dissector crash, different
    from wpna-sec-2016-30 (bsc#983671)

  - CVE-2016-5353: UMTS FP crash (bsc#983671)

  - CVE-2016-5354: USB dissector crash (bsc#983671)

  - CVE-2016-5355: Toshiba file parser crash (bsc#983671)

  - CVE-2016-5356: CoSine file parser crash (bsc#983671)

  - CVE-2016-5357: NetScreen file parser crash (bsc#983671)

  - CVE-2016-5358: Ethernet dissector crash (bsc#983671)

  - CVE-2016-5359: WBXML infinite loop (bsc#983671) For more
    details please see:
    https://www.wireshark.org/docs/relnotes/wireshark-1.12.1
    2.html
    https://www.wireshark.org/docs/relnotes/wireshark-1.12.1
    3.html

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983671"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/991012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/991013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/991015"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/991016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/991017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/991018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/991019"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/991020"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5350.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5351.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5352.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5353.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5354.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5355.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5356.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5357.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5358.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5359.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6504.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6505.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6506.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6507.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6508.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6509.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6510.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6511.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162212-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2f19d30a"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/docs/relnotes/wireshark-1.12.12.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/docs/relnotes/wireshark-1.12.13.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-wireshark-12725=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-wireshark-12725=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-wireshark-12725=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", reference:"wireshark-1.12.13-0.23.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark");
}
