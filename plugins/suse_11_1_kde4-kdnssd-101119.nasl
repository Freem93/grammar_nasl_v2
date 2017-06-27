#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kde4-kdnssd-3561.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(53664);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/06/13 19:49:34 $");

  script_cve_id("CVE-2008-4776", "CVE-2010-1000");

  script_name(english:"openSUSE Security Update : kde4-kdnssd (openSUSE-SU-2010:1077-1)");
  script_summary(english:"Check for the kde4-kdnssd-3561 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of kdenetwork fixes several bugs, the security related
issues are :

  - CVE-2010-1000: CVSS v2 Base Score: 4.3
    (AV:N/AC:M/Au:N/C:N/I:P/A:N): CWE-22 The 'name'
    attribute of the 'file' element of metalink files is not
    properly sanitised this can be exploited to download
    files to arbitrary directories.

  - CVE-2008-4776: CVSS v2 Base Score: 4.3
    (AV:N/AC:M/Au:N/C:N/I:N/A:P): CWE-119 The included
    libgadu version allowed remote servers to cause a denial
    of service (crash) via a buffer over-read.

Non-security issues :

  - bnc#653852: kopete: ICQ login broken; login server
    changed

  - bnc#516347: kopete cant connect to yahoo"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2010-12/msg00043.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=516347"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=525528"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=604709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=653852"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kde4-kdnssd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kde4-kdnssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kde4-kget");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kde4-knewsticker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kde4-kopete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kde4-kopete-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kde4-kppp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kde4-krdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kde4-krfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdenetwork4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdenetwork4-filesharing");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.1", reference:"kde4-kdnssd-4.1.3-4.15.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kde4-kget-4.1.3-4.15.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kde4-knewsticker-4.1.3-4.15.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kde4-kopete-4.1.3-4.15.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kde4-kopete-devel-4.1.3-4.15.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kde4-kppp-4.1.3-4.15.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kde4-krdc-4.1.3-4.15.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kde4-krfb-4.1.3-4.15.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kdenetwork4-4.1.3-4.15.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kdenetwork4-filesharing-4.1.3-4.15.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdenetwork");
}
