#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-559.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(85703);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/08/31 14:21:58 $");

  script_cve_id("CVE-2015-4473", "CVE-2015-4475", "CVE-2015-4478", "CVE-2015-4479", "CVE-2015-4480", "CVE-2015-4481", "CVE-2015-4482", "CVE-2015-4484", "CVE-2015-4485", "CVE-2015-4486", "CVE-2015-4487", "CVE-2015-4488", "CVE-2015-4489", "CVE-2015-4491", "CVE-2015-4492", "CVE-2015-4493");

  script_name(english:"openSUSE Security Update : MozillaThunderbird (openSUSE-2015-559)");
  script_summary(english:"Check for the openSUSE-2015-559 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update to Thunderbird 38.2.0 fixes the following issues
(bnc#940806) :

  - MFSA 2015-79/CVE-2015-4473 Miscellaneous memory safety
    hazards

  - MFSA 2015-80/CVE-2015-4475 (bmo#1175396) Out-of-bounds
    read with malformed MP3 file

  - MFSA 2015-82/CVE-2015-4478 (bmo#1105914) Redefinition of
    non-configurable JavaScript object properties

  - MFSA 2015-83/CVE-2015-4479/CVE-2015-4480/CVE-2015-4493
    Overflow issues in libstagefright

  - MFSA 2015-84/CVE-2015-4481 (bmo1171518) Arbitrary file
    overwriting through Mozilla Maintenance Service with
    hard links (only affected Windows)

  - MFSA 2015-85/CVE-2015-4482 (bmo#1184500) Out-of-bounds
    write with Updater and malicious MAR file (does not
    affect openSUSE RPM packages which do not ship the
    updater)

  - MFSA 2015-87/CVE-2015-4484 (bmo#1171540) Crash when
    using shared memory in JavaScript

  - MFSA 2015-88/CVE-2015-4491 (bmo#1184009) Heap overflow
    in gdk-pixbuf when scaling bitmap images

  - MFSA 2015-89/CVE-2015-4485/CVE-2015-4486 (bmo#1177948,
    bmo#1178148) Buffer overflows on Libvpx when decoding
    WebM video

  - MFSA 2015-90/CVE-2015-4487/CVE-2015-4488/CVE-2015-4489
    Vulnerabilities found through code inspection

  - MFSA 2015-92/CVE-2015-4492 (bmo#1185820) Use-after-free
    in XMLHttpRequest with shared workers"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=940806"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaThunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-38.2.0-25.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-buildsymbols-38.2.0-25.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-debuginfo-38.2.0-25.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-debugsource-38.2.0-25.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-devel-38.2.0-25.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-translations-common-38.2.0-25.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-translations-other-38.2.0-25.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaThunderbird / MozillaThunderbird-buildsymbols / etc");
}
