#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-734.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(91640);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/13 14:37:12 $");

  script_cve_id("CVE-2016-1762", "CVE-2016-1833", "CVE-2016-1834", "CVE-2016-1835", "CVE-2016-1836", "CVE-2016-1837", "CVE-2016-1838", "CVE-2016-1839", "CVE-2016-1840", "CVE-2016-3627", "CVE-2016-3705", "CVE-2016-4483");

  script_name(english:"openSUSE Security Update : libxml2 (openSUSE-2016-734)");
  script_summary(english:"Check for the openSUSE-2016-734 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update brings libxml2 to version 2.9.4.

These security issues were fixed :

  - CVE-2016-3627: The xmlStringGetNodeList function in
    tree.c, when used in recovery mode, allowed
    context-dependent attackers to cause a denial of service
    (infinite recursion, stack consumption, and application
    crash) via a crafted XML document (bsc#972335).

  - CVE-2016-1833: libxml2 allowed remote attackers to
    execute arbitrary code or cause a denial of service
    (memory corruption) via a crafted XML document, a
    different vulnerability than CVE-2016-1834,
    CVE-2016-1836, CVE-2016-1837, CVE-2016-1838,
    CVE-2016-1839, and CVE-2016-1840 (bsc#981108).

  - CVE-2016-1835: libxml2 allowed remote attackers to
    execute arbitrary code or cause a denial of service
    (memory corruption) via a crafted XML document
    (bsc#981109).

  - CVE-2016-1837: libxml2 allowed remote attackers to
    execute arbitrary code or cause a denial of service
    (memory corruption) via a crafted XML document, a
    different vulnerability than CVE-2016-1833,
    CVE-2016-1834, CVE-2016-1836, CVE-2016-1838,
    CVE-2016-1839, and CVE-2016-1840 (bsc#981111).

  - CVE-2016-1836: libxml2 allowed remote attackers to
    execute arbitrary code or cause a denial of service
    (memory corruption) via a crafted XML document, a
    different vulnerability than CVE-2016-1833,
    CVE-2016-1834, CVE-2016-1837, CVE-2016-1838,
    CVE-2016-1839, and CVE-2016-1840 (bsc#981110).

  - CVE-2016-1839: libxml2 allowed remote attackers to
    execute arbitrary code or cause a denial of service
    (memory corruption) via a crafted XML document, a
    different vulnerability than CVE-2016-1833,
    CVE-2016-1834, CVE-2016-1836, CVE-2016-1837,
    CVE-2016-1838, and CVE-2016-1840 (bsc#981114).

  - CVE-2016-1838: libxml2 allowed remote attackers to
    execute arbitrary code or cause a denial of service
    (memory corruption) via a crafted XML document, a
    different vulnerability than CVE-2016-1833,
    CVE-2016-1834, CVE-2016-1836, CVE-2016-1837,
    CVE-2016-1839, and CVE-2016-1840 (bsc#981112).

  - CVE-2016-1840: libxml2 allowed remote attackers to
    execute arbitrary code or cause a denial of service
    (memory corruption) via a crafted XML document, a
    different vulnerability than CVE-2016-1833,
    CVE-2016-1834, CVE-2016-1836, CVE-2016-1837,
    CVE-2016-1838, and CVE-2016-1839 (bsc#981115).

  - CVE-2016-4483: out-of-bounds read parsing an XML using
    recover mode (bnc#978395).

  - CVE-2016-1834: libxml2 allowed remote attackers to
    execute arbitrary code or cause a denial of service
    (memory corruption) via a crafted XML document, a
    different vulnerability than CVE-2016-1833,
    CVE-2016-1836, CVE-2016-1837, CVE-2016-1838,
    CVE-2016-1839, and CVE-2016-1840 (bsc#981041).

  - CVE-2016-3705: The (1) xmlParserEntityCheck and (2)
    xmlParseAttValueComplex functions in parser.c in libxml2
    did not properly keep track of the recursion depth,
    which allowed context-dependent attackers to cause a
    denial of service (stack consumption and application
    crash) via a crafted XML document containing a large
    number of nested entity references (bsc#975947).

  - CVE-2016-1762: libxml2 allowed remote attackers to
    execute arbitrary code or cause a denial of service
    (memory corruption) via a crafted XML document
    (bsc#981040).

This non-security issue was fixed :

  - bnc#983288: Fix attribute decoding during XML schema
    validation"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=972335"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=975947"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978395"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=981040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=981041"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=981108"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=981109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=981110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=981111"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=981112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=981114"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=981115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983288"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxml2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-libxml2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-libxml2-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/17");
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

if ( rpm_check(release:"SUSE13.2", reference:"libxml2-2-2.9.4-7.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxml2-2-debuginfo-2.9.4-7.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxml2-debugsource-2.9.4-7.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxml2-devel-2.9.4-7.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxml2-tools-2.9.4-7.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxml2-tools-debuginfo-2.9.4-7.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-libxml2-2.9.4-7.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-libxml2-debuginfo-2.9.4-7.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-libxml2-debugsource-2.9.4-7.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxml2-2-32bit-2.9.4-7.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxml2-2-debuginfo-32bit-2.9.4-7.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxml2-devel-32bit-2.9.4-7.17.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2-2 / libxml2-2-32bit / libxml2-2-debuginfo / etc");
}
