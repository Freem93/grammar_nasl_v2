#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-409.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74686);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/07/21 13:37:21 $");

  script_cve_id("CVE-2012-2370");
  script_osvdb_id(81924);

  script_name(english:"openSUSE Security Update : gdk-pixbuf (openSUSE-SU-2012:0897-1)");
  script_summary(english:"Check for the openSUSE-2012-409 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Fix integer overflow in XBM file loader. Fix bnc#762735,
CVE-2012-2370."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-07/msg00037.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=762735"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gdk-pixbuf packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-query-loaders");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-query-loaders-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-query-loaders-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-query-loaders-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgdk_pixbuf-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgdk_pixbuf-2_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgdk_pixbuf-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgdk_pixbuf-2_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.4|SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4 / 12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"gdk-pixbuf-debugsource-2.22.1-7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"gdk-pixbuf-devel-2.22.1-7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"gdk-pixbuf-devel-debuginfo-2.22.1-7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"gdk-pixbuf-lang-2.22.1-7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"gdk-pixbuf-query-loaders-2.22.1-7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"gdk-pixbuf-query-loaders-debuginfo-2.22.1-7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libgdk_pixbuf-2_0-0-2.22.1-7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libgdk_pixbuf-2_0-0-debuginfo-2.22.1-7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"gdk-pixbuf-query-loaders-32bit-2.22.1-7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"gdk-pixbuf-query-loaders-debuginfo-32bit-2.22.1-7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libgdk_pixbuf-2_0-0-32bit-2.22.1-7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libgdk_pixbuf-2_0-0-debuginfo-32bit-2.22.1-7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"gdk-pixbuf-debugsource-2.24.0-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"gdk-pixbuf-devel-2.24.0-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"gdk-pixbuf-devel-debuginfo-2.24.0-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"gdk-pixbuf-lang-2.24.0-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"gdk-pixbuf-query-loaders-2.24.0-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"gdk-pixbuf-query-loaders-debuginfo-2.24.0-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libgdk_pixbuf-2_0-0-2.24.0-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libgdk_pixbuf-2_0-0-debuginfo-2.24.0-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"gdk-pixbuf-query-loaders-32bit-2.24.0-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"gdk-pixbuf-query-loaders-debuginfo-32bit-2.24.0-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libgdk_pixbuf-2_0-0-32bit-2.24.0-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libgdk_pixbuf-2_0-0-debuginfo-32bit-2.24.0-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gdk-pixbuf");
}
