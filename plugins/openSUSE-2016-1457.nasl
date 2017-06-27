#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1457.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(95792);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2016/12/21 14:22:37 $");

  script_cve_id("CVE-2016-9434", "CVE-2016-9435", "CVE-2016-9436", "CVE-2016-9437", "CVE-2016-9438", "CVE-2016-9439", "CVE-2016-9440", "CVE-2016-9441", "CVE-2016-9442", "CVE-2016-9443", "CVE-2016-9621", "CVE-2016-9622", "CVE-2016-9623", "CVE-2016-9624", "CVE-2016-9625", "CVE-2016-9626", "CVE-2016-9627", "CVE-2016-9628", "CVE-2016-9629", "CVE-2016-9630", "CVE-2016-9631", "CVE-2016-9632", "CVE-2016-9633");

  script_name(english:"openSUSE Security Update : w3m (openSUSE-2016-1457)");
  script_summary(english:"Check for the openSUSE-2016-1457 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for w3m fixes the following security issues 
(bsc#1011293) :

  - CVE-2016-9622: w3m: null deref (bsc#1012021)

  - CVE-2016-9623: w3m: null deref (bsc#1012022)

  - CVE-2016-9624: w3m: near-null deref (bsc#1012023)

  - CVE-2016-9625: w3m: stack overflow (bsc#1012024)

  - CVE-2016-9626: w3m: stack overflow (bsc#1012025)

  - CVE-2016-9627: w3m: heap overflow read + deref
    (bsc#1012026)

  - CVE-2016-9628: w3m: null deref (bsc#1012027)

  - CVE-2016-9629: w3m: null deref (bsc#1012028)

  - CVE-2016-9630: w3m: global-buffer-overflow read
    (bsc#1012029)

  - CVE-2016-9631: w3m: null deref (bsc#1012030)

  - CVE-2016-9632: w3m: global-buffer-overflow read
    (bsc#1012031)

  - CVE-2016-9633: w3m: OOM (bsc#1012032)

  - CVE-2016-9434: w3m: null deref (bsc#1011283)

  - CVE-2016-9435: w3m: use uninit value (bsc#1011284)

  - CVE-2016-9436: w3m: use uninit value (bsc#1011285)

  - CVE-2016-9437: w3m: write to rodata (bsc#1011286)

  - CVE-2016-9438: w3m: null deref (bsc#1011287)

  - CVE-2016-9439: w3m: stack overflow (bsc#1011288)

  - CVE-2016-9440: w3m: near-null deref (bsc#1011289)

  - CVE-2016-9441: w3m: near-null deref (bsc#1011290)

  - CVE-2016-9442: w3m: potential heap buffer corruption
    (bsc#1011291)

  - CVE-2016-9443: w3m: null deref (bsc#1011292)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011283"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011286"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011287"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011288"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011289"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011290"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011291"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011292"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011293"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012022"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012023"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012027"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012028"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012029"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012030"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012031"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012032"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected w3m packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:w3m");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:w3m-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:w3m-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:w3m-inline-image");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:w3m-inline-image-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/14");
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
if (release !~ "^(SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"w3m-0.5.3.git20161120-161.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"w3m-debuginfo-0.5.3.git20161120-161.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"w3m-debugsource-0.5.3.git20161120-161.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"w3m-inline-image-0.5.3.git20161120-161.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"w3m-inline-image-debuginfo-0.5.3.git20161120-161.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"w3m-0.5.3.git20161120-160.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"w3m-debuginfo-0.5.3.git20161120-160.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"w3m-debugsource-0.5.3.git20161120-160.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"w3m-inline-image-0.5.3.git20161120-160.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"w3m-inline-image-debuginfo-0.5.3.git20161120-160.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "w3m / w3m-debuginfo / w3m-debugsource / w3m-inline-image / etc");
}
