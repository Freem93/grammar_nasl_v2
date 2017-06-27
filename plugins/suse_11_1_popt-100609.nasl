#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update popt-2531.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(49265);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/06/13 19:55:05 $");

  script_cve_id("CVE-2010-2059");

  script_name(english:"openSUSE Security Update : popt (openSUSE-SU-2010:0629-1)");
  script_summary(english:"Check for the popt-2531 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the problem where RPM misses to clear the SUID/SGID
bit of old files during package updates. (CVE-2010-2059)

Also following bugfixes were merged from SLE11 :

  - make 'rpmconfigcheck status' exit with 4 [bnc#592269]

  - do not use glibc for passwd/group lookups when --root is
    used [bnc#536256]

  - disable cpio md5 checking for repackaged rpms
    [bnc#572280]

  - Add rpm-4.4.2.3-no-order-rescan-limit.patch from
    upstream (bnc#552622)

  - backport lazy statfs patch [fate#302038]

  - define disttag as optional tag with macro just like
    disturl 

  - add popt-devel and rpm-devel to baselibs config
    (bnc#445037)

  - brp-symlink: whitelist kde4 doc path (bnc#457908) 

  - find-supplements.ksyms: Module aliases may contain
    special characters that rpm does not allow in
    dependencies, such as commas. Encode those as %XX to
    avoid generating broken dependencies (bnc#456695).

  - find-debuginfo.sh: Don't convert to binary."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2010-09/msg00028.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=445037"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=456695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=457908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=536256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=552622"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=572280"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=592269"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=610941"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected popt packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:popt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:popt-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:popt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rpm-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rpm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rpm-devel-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/17");
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
if (release !~ "^(SUSE11\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.1", reference:"popt-1.7-20.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"popt-devel-1.7-20.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"rpm-4.4.2.3-20.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"rpm-devel-4.4.2.3-20.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"rpm-devel-static-4.4.2.3-20.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"popt-32bit-1.7-20.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"rpm-32bit-4.4.2.3-20.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rpm");
}
