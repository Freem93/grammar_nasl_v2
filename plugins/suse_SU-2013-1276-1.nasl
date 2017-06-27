#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2013:1276-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83596);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/20 15:11:10 $");

  script_cve_id("CVE-2013-2486", "CVE-2013-2487", "CVE-2013-3555", "CVE-2013-3556", "CVE-2013-3557", "CVE-2013-3558", "CVE-2013-3559", "CVE-2013-3560", "CVE-2013-3561", "CVE-2013-3562", "CVE-2013-4074", "CVE-2013-4075", "CVE-2013-4076", "CVE-2013-4077", "CVE-2013-4078", "CVE-2013-4079", "CVE-2013-4080", "CVE-2013-4081", "CVE-2013-4082", "CVE-2013-4083");
  script_bugtraq_id(58363, 58364, 59992, 59994, 59995, 59996, 59997, 59998, 59999, 60000, 60001, 60002, 60003, 60021, 60448, 60495, 60498, 60499, 60500, 60501, 60502, 60503, 60504, 60505, 60506);

  script_name(english:"SUSE SLED10 / SLES10 Security Update : wireshark (SUSE-SU-2013:1276-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This wireshark version update to 1.6.16 includes several security and
general bug fixes.

http://www.wireshark.org/docs/relnotes/wireshark-1.6.16.html

  - The CAPWAP dissector could crash. Discovered by Laurent
    Butti. (CVE-2013-4074)

  - The HTTP dissector could overrun the stack. Discovered
    by David Keeler. (CVE-2013-4081)

  - The DCP ETSI dissector could crash. (CVE-2013-4083)

http://www.wireshark.org/docs/relnotes/wireshark-1.6.15.html

  - The ASN.1 BER dissector could crash. ( CVE-2013-3556
    CVE-2013-3557 )

The releases also fix various non-security issues.

Additionally, a crash in processing SCTP filters has been fixed.
(bug#816887)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=cb4504a53f9b3d0625f514d688e2c947
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?023b8157"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2486.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2487.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3555.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3556.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3557.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3558.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3559.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3560.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3561.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3562.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4074.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4075.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4076.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4077.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4078.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4079.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4080.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4081.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4082.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4083.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.wireshark.org/docs/relnotes/wireshark-1.6.15.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.wireshark.org/docs/relnotes/wireshark-1.6.16.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/816887"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/820973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/824900"
  );
  # https://www.suse.com/support/update/announcement/2013/suse-su-20131276-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4e71c4a9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(SLED10|SLES10)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED10 / SLES10", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED10" && (! ereg(pattern:"^4$", string:sp))) audit(AUDIT_OS_NOT, "SLED10 SP4", os_ver + " SP" + sp);
if (os_ver == "SLES10" && (! ereg(pattern:"^4$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"wireshark-1.6.16-0.5.5")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"wireshark-1.6.16-0.5.5")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"wireshark-1.6.16-0.5.5")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"wireshark-devel-1.6.16-0.5.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark");
}
