#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update xorg-x11-Xvnc-5766.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(76051);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 22:19:38 $");

  script_cve_id("CVE-2010-4818");

  script_name(english:"openSUSE Security Update : xorg-x11-Xvnc (openSUSE-SU-2012:0307-1)");
  script_summary(english:"Check for the xorg-x11-Xvnc-5766 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of xorg-x11-server fixes issues that could allow attackers
read access to arbitrary memory locations via the GLX protocol
(CVE-2010-4818)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-02/msg00062.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=648287"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xorg-x11-Xvnc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-Xvnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-Xvnc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-sdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/07");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"xorg-x11-Xvnc-7.6_1.9.3-15.26.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xorg-x11-Xvnc-debuginfo-7.6_1.9.3-15.26.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xorg-x11-server-7.6_1.9.3-15.26.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xorg-x11-server-debuginfo-7.6_1.9.3-15.26.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xorg-x11-server-debugsource-7.6_1.9.3-15.26.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xorg-x11-server-extra-7.6_1.9.3-15.26.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xorg-x11-server-extra-debuginfo-7.6_1.9.3-15.26.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xorg-x11-server-sdk-7.6_1.9.3-15.26.1") ) flag++;

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
