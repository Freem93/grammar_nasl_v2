#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-400.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75378);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:39:49 $");

  script_cve_id("CVE-2013-6487", "CVE-2014-3775");
  script_bugtraq_id(65188, 67471);

  script_name(english:"openSUSE Security Update : libgadu (openSUSE-SU-2014:0722-1)");
  script_summary(english:"Check for the openSUSE-2014-400 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Update to version 1.11.4, bugfix release :

  + Fix buffer overflow with remote code execution
    potential. Only triggerable by a Gadu-Gadu server or a
    man-in-the-middle. CVE-2013-6487 (bnc#861019,
    bnc#878540)

  + Fix memory overwrite in file transfer with proxy server.
    CVE-2014-3775 (bnc#878540)

  + Minor fixes reported by Pidgin project members."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-05/msg00082.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=878540"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libgadu packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgadu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgadu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgadu3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgadu3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/21");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"libgadu-debugsource-1.11.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libgadu-devel-1.11.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libgadu3-1.11.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libgadu3-debuginfo-1.11.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgadu-debugsource-1.11.4-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgadu-devel-1.11.4-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgadu3-1.11.4-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgadu3-debuginfo-1.11.4-4.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libgadu-debugsource / libgadu-devel / libgadu3 / libgadu3-debuginfo");
}
