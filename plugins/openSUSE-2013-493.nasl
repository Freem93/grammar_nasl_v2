#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-493.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75034);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-1923");

  script_name(english:"openSUSE Security Update : nfs-utils (openSUSE-SU-2013:1016-1)");
  script_summary(english:"Check for the openSUSE-2013-493 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of nfs-utils includes several bug and security fixes.

  - gssd-reverse-dns-fix: Allow DNS lookups to be avoided
    when determining kerberos identity of server. The
    GSSD_OPTIONS sysconfig variable is added so that use of
    DNS can be enforced for sites that need it. (bnc#813464
    CVE-2013-1923)

  - gssd-n.fix: linux-3.7 changed behaviour of gssd lookups
    so that 'gssd -n' isn't sufficient to stop the use of
    'machine credentials'. This patch add '-N' which stops
    the new use as well. Also add GSSD_OPTIONS to sysconfig
    so these flags can be set more easily. (bnc#817651)

  - mountd-fix-exporting-of-with-sec-setting.patch Fix bug
    when exporting root filesystem with gss security.
    (bnc#809226)

  - mountd-fix-error-check.patch: check for errors with
    exporting filesystems correctly (bnc#809226)

  - nfsserver.init: make sure warning about bind= being
    deprecated goes to terminal and not into
    /run/nfs/bind.mounts (bnc#809226)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-06/msg00146.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=809226"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=813464"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=817651"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nfs-utils packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nfs-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nfs-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nfs-kernel-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nfs-kernel-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nfs-utils-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/04");
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
if (release !~ "^(SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"nfs-client-1.2.7-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"nfs-client-debuginfo-1.2.7-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"nfs-kernel-server-1.2.7-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"nfs-kernel-server-debuginfo-1.2.7-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"nfs-utils-debugsource-1.2.7-2.6.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nfs-client / nfs-client-debuginfo / nfs-kernel-server / etc");
}
