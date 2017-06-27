#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-120.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74892);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:12 $");

  script_cve_id("CVE-2013-0240");
  script_osvdb_id(89961);

  script_name(english:"openSUSE Security Update : gnome-online-accounts (openSUSE-SU-2013:0301-1)");
  script_summary(english:"Check for the openSUSE-2013-120 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"gnome-online-accounts was updated to do SSL certicicate checking when
creating accounts, avoiding man-in-the-middle attack possibilities.
(CVE-2013--240)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-02/msg00046.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.gnome.org/show_bug.cgi?id=693214"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=802409"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnome-online-accounts packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnome-online-accounts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnome-online-accounts-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnome-online-accounts-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnome-online-accounts-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnome-online-accounts-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgoa-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgoa-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgoa-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgoa-1_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgoa-backend-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgoa-backend-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgoa-backend-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgoa-backend-1_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-Goa-1_0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/07");
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
if (release !~ "^(SUSE12\.1|SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1 / 12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"gnome-online-accounts-3.2.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"gnome-online-accounts-debuginfo-3.2.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"gnome-online-accounts-debugsource-3.2.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"gnome-online-accounts-devel-3.2.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"gnome-online-accounts-lang-3.2.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libgoa-1_0-0-3.2.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libgoa-1_0-0-debuginfo-3.2.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libgoa-backend-1_0-0-3.2.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libgoa-backend-1_0-0-debuginfo-3.2.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gnome-online-accounts-3.4.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gnome-online-accounts-debuginfo-3.4.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gnome-online-accounts-debugsource-3.4.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gnome-online-accounts-devel-3.4.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gnome-online-accounts-lang-3.4.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libgoa-1_0-0-3.4.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libgoa-1_0-0-debuginfo-3.4.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libgoa-backend-1_0-0-3.4.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libgoa-backend-1_0-0-debuginfo-3.4.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"typelib-1_0-Goa-1_0-3.4.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libgoa-1_0-0-32bit-3.4.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libgoa-1_0-0-debuginfo-32bit-3.4.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libgoa-backend-1_0-0-32bit-3.4.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libgoa-backend-1_0-0-debuginfo-32bit-3.4.2-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnome-online-accounts");
}
