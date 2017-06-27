#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update libtiff-devel-2477.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(47019);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/06/13 19:44:02 $");

  script_cve_id("CVE-2010-1411");

  script_name(english:"openSUSE Security Update : libtiff-devel (openSUSE-SU-2010:0324-1)");
  script_summary(english:"Check for the libtiff-devel-2477 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of libtiff fixes several integer overflows that could lead
to a corrupted heap memory. This bug can be exploited remotely with a
crafted TIFF file to cause an application crash or probably to execute
arbitrary code. (CVE-2010-1411)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2010-06/msg00003.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=605837"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libtiff-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tiff");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.0", reference:"libtiff-devel-3.8.2-108.9") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libtiff3-3.8.2-108.9") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"tiff-3.8.2-108.9") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"libtiff-devel-32bit-3.8.2-108.9") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"libtiff3-32bit-3.8.2-108.9") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtiff");
}
