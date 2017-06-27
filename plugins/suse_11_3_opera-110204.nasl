#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update opera-3919.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75694);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:55:23 $");

  script_cve_id("CVE-2011-0681", "CVE-2011-0682", "CVE-2011-0683", "CVE-2011-0684", "CVE-2011-0685", "CVE-2011-0686", "CVE-2011-0687");

  script_name(english:"openSUSE Security Update : opera (openSUSE-SU-2011:0103-1)");
  script_summary(english:"Check for the opera-3919 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Opera 11.01 fixes several critical security bugs :

  - CVE-2011-0681: CVSS v2 Base Score: 4.3 (MEDIUM)
    (AV:N/AC:M/Au:N/C:N/I:P/A:N): Other (CWE-Other)

  - CVE-2011-0682: CVSS v2 Base Score: 9.3 (HIGH)
    (AV:N/AC:M/Au:N/C:C/I:C/A:C): Buffer Errors (CWE-119)

  - CVE-2011-0683: CVSS v2 Base Score: 4.3 (MEDIUM)
    (AV:N/AC:M/Au:N/C:N/I:P/A:N): Other (CWE-Other)

  - CVE-2011-0684: CVSS v2 Base Score: 7.8 (HIGH)
    (AV:N/AC:L/Au:N/C:C/I:N/A:N): Input Validation (CWE-20)

  - CVE-2011-0685: CVSS v2 Base Score: 3.6 (LOW)
    (AV:L/AC:L/Au:N/C:P/I:P/A:N): Input Validation (CWE-20)

  - CVE-2011-0686: CVSS v2 Base Score: 5.0 (MEDIUM)
    (AV:N/AC:L/Au:N/C:N/I:N/A:P): Insufficient Information
    (CWE-noinfo)

  - CVE-2011-0687: CVSS v2 Base Score: 4.3 (MEDIUM)
    (AV:N/AC:M/Au:N/C:N/I:N/A:P): Input Validation (CWE-20)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-02/msg00004.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=667639"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected opera packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opera-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opera-kde4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.3", reference:"opera-11.01-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"opera-gtk-11.01-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"opera-kde4-11.01-1.2.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "opera / opera-gtk / opera-kde4");
}
