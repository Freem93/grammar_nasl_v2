#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update xorg-x11-Xvnc-2973.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75779);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 22:10:32 $");

  script_cve_id("CVE-2010-1166", "CVE-2010-2240");

  script_name(english:"openSUSE Security Update : xorg-x11-Xvnc (openSUSE-SU-2010:0561-1)");
  script_summary(english:"Check for the xorg-x11-Xvnc-2973 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The X.Org X11 Server was updated to fix several bugs and 2 security
issues :

Two security issues were fixed: CVE-2010-2240: This fix adds a
workaround for overlapping stacks and heaps in case of OOM
conditions.This workaround is necessary if the kernel is not properly
adding guard or gap-pages below the stack. 

CVE-2010-1166: The fbComposite function in fbpict.c in the Render
extension in the X server in X.Org X11R7.1 allows remote authenticated
users to cause a denial of service (memory corruption and daemon
crash) or possibly execute arbitrary code via a crafted request,
related to an incorrect macro definition.

Non-Security Bugs fixed: Fix some shortcomings in the Xdmcp
implementation. It used to suppress loopback addresses from the list
of potential display addresses to report to xdm, even when talking to
xdm through a loopback address. Now only display addresses of the same
kind as the xdm connection are reported to xdm.

This most notably helps Xvnc servers contacting the local xdm, because
they were severely affected by the suppression of loopback addresses."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2010-08/msg00064.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=546632"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=597232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=618152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=623254"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=625593"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xorg-x11-Xvnc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-Xvnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-sdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/19");
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

if ( rpm_check(release:"SUSE11.3", reference:"xorg-x11-Xvnc-7.5_1.8.0-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"xorg-x11-server-7.5_1.8.0-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"xorg-x11-server-extra-7.5_1.8.0-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"xorg-x11-server-sdk-7.5_1.8.0-10.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11-server");
}
