#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-349.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(89975);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/13 14:27:29 $");

  script_cve_id("CVE-2016-1521", "CVE-2016-1522", "CVE-2016-1523", "CVE-2016-1526");

  script_name(english:"openSUSE Security Update : graphite2 (openSUSE-2016-349)");
  script_summary(english:"Check for the openSUSE-2016-349 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for graphite2 fixes the following issues :

  - CVE-2016-1521: The directrun function in
    directmachine.cpp in Libgraphite did not validate a
    certain skip operation, which allowed remote attackers
    to execute arbitrary code, obtain sensitive information,
    or cause a denial of service (out-of-bounds read and
    application crash) via a crafted Graphite smart font.

  - CVE-2016-1522: Code.cpp in Libgraphite did not consider
    recursive load calls during a size check, which allowed
    remote attackers to cause a denial of service
    (heap-based buffer overflow) or possibly execute
    arbitrary code via a crafted Graphite smart font.

  - CVE-2016-1523: The SillMap::readFace function in
    FeatureMap.cpp in Libgraphite mishandled a return value,
    which allowed remote attackers to cause a denial of
    service (missing initialization, NULL pointer
    dereference, and application crash) via a crafted
    Graphite smart font.

  - CVE-2016-1526: The TtfUtil:LocaLookup function in
    TtfUtil.cpp in Libgraphite incorrectly validated a size
    value, which allowed remote attackers to obtain
    sensitive information or cause a denial of service
    (out-of-bounds read and application crash) via a crafted
    Graphite smart font."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=965803"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=965806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=965807"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=965810"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected graphite2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphite2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphite2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphite2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphite2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgraphite2-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgraphite2-3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgraphite2-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgraphite2-3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"graphite2-1.2.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"graphite2-debuginfo-1.2.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"graphite2-debugsource-1.2.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"graphite2-devel-1.2.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgraphite2-3-1.2.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgraphite2-3-debuginfo-1.2.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgraphite2-3-32bit-1.2.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgraphite2-3-debuginfo-32bit-1.2.4-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "graphite2 / graphite2-debuginfo / graphite2-debugsource / etc");
}
