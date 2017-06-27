#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update xorg-x11-Xvnc-5317.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(33165);
  script_version ("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/06/13 20:41:30 $");

  script_cve_id("CVE-2007-3920", "CVE-2008-1377", "CVE-2008-1379", "CVE-2008-2360", "CVE-2008-2361", "CVE-2008-2362");

  script_name(english:"openSUSE 10 Security Update : xorg-x11-Xvnc (xorg-x11-Xvnc-5317)");
  script_summary(english:"Check for the xorg-x11-Xvnc-5317 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes multiple vulnerabilities reported by iDefense :

  - CVE-2008-2360 - RENDER Extension heap buffer overflow

  - CVE-2008-2361 - RENDER Extension crash

  - CVE-2008-2362 - RENDER Extension memory corruption 

  - CVE-2008-1379 - MIT-SHM arbitrary memory read

  - CVE-2008-1377 - RECORD and Security extensions memory
    corruption Additionally fixes for :

  - XvReputImage crashes due to Nulled PortPriv->pDraw

  - gnome-screensaver loses keyboard focus lock under compiz
    (CVE-2007-3920)"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xorg-x11-Xvnc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-Xvnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-sdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.3", reference:"xorg-x11-Xvnc-7.1-91.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"xorg-x11-server-7.2-143.13") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"xorg-x11-server-extra-7.2-143.13") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"xorg-x11-server-sdk-7.2-143.13") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11-Xvnc / xorg-x11-server / xorg-x11-server-extra / etc");
}
