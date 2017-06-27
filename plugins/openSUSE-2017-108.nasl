#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-108.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(96580);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/01/18 14:49:21 $");

  script_cve_id("CVE-2016-7445", "CVE-2016-8332", "CVE-2016-9112", "CVE-2016-9113", "CVE-2016-9114", "CVE-2016-9115", "CVE-2016-9116", "CVE-2016-9117", "CVE-2016-9118", "CVE-2016-9572", "CVE-2016-9573", "CVE-2016-9580", "CVE-2016-9581");

  script_name(english:"openSUSE Security Update : openjpeg2 (openSUSE-2017-108)");
  script_summary(english:"Check for the openSUSE-2017-108 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for openjpeg2 fixes the following issues :

  - CVE-2016-9572 CVE-2016-9573: Insuficient check in
    imagetopnm() could lead to heap buffer overflow
    [bsc#1014543]

  - CVE-2016-9580, CVE-2016-9581: Possible Heap buffer
    overflow via integer overflow and infite loop
    [bsc#1014975]

  - CVE-2016-7445: NULL pointer dereference in convert.c
    could lead to crash [bsc#999817]

  - CVE-2016-8332: Malicious file in OpenJPEG JPEG2000
    format could lead to code execution [bsc#1002414]

  - CVE-2016-9112: FPE(Floating Point Exception) in
    lib/openjp2/pi.c:523 [bsc#1007747]

  - CVE-2016-9113: NULL point dereference in function
    imagetobmp of convertbmp.c could lead to crash
    [bsc#1007739]

  - CVE-2016-9114: NULL pointer Access in function
    imagetopnm of convert.c:1943(jp2) could lead to crash
    [bsc#1007740]

  - CVE-2016-9115: Heap Buffer Overflow in function
    imagetotga of convert.c(jp2) [bsc#1007741]

  - CVE-2016-9116: NULL pointer Access in function
    imagetopnm of convert.c:2226(jp2) [bsc#1007742]

  - CVE-2016-9117: NULL pointer Access in function
    imagetopnm of convert.c(jp2):1289 [bsc#1007743]

  - CVE-2016-9118: Heap Buffer Overflow in function
    pnmtoimage of convert.c [bsc#1007744]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1002414"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007740"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007741"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007742"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007743"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007744"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007747"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1014543"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1014975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=999817"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openjpeg2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenjp2-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenjp2-7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openjpeg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openjpeg2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openjpeg2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openjpeg2-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE13.2", reference:"libopenjp2-7-2.1.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libopenjp2-7-debuginfo-2.1.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"openjpeg2-2.1.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"openjpeg2-debuginfo-2.1.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"openjpeg2-debugsource-2.1.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"openjpeg2-devel-2.1.0-2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libopenjp2-7 / libopenjp2-7-debuginfo / openjpeg2 / etc");
}
