#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-258.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74613);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2012-2111");

  script_name(english:"openSUSE Security Update : samba (openSUSE-SU-2012:0583-1)");
  script_summary(english:"Check for the openSUSE-2012-258 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - docs-xml: fix default name resolve order; (bso#7564).

  - s3-aio-fork: Fix a segfault in vfs_aio_fork; (bso#8836).

  - docs: remove whitespace in example samba.ldif;
    (bso#8789).

  - s3-smbd: move print_backend_init() behind
    init_system_info(); (bso#8845).

  - s3-docs: Prepend '/' to filename argument; (bso#8826).

  - Restrict self granting privileges where security=ads for
    Samba post-3.3.16; CVE-2012-2111; (bnc#757576)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-05/msg00003.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=757576"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=7564"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=8789"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=8826"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=8836"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=8845"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ldapsmb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldb1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldb1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldb1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbsharemodes-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbsharemodes0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbsharemodes0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtalloc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtalloc2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtalloc2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtalloc2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtalloc2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtdb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtdb1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtdb1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtdb1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-krb-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-krb-printing-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/02");
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
if (release !~ "^(SUSE11\.4|SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4 / 12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"ldapsmb-1.34b-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libldb-devel-1.0.2-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libldb1-1.0.2-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libldb1-debuginfo-1.0.2-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libnetapi-devel-3.6.3-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libnetapi0-3.6.3-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libnetapi0-debuginfo-3.6.3-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libsmbclient-devel-3.6.3-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libsmbclient0-3.6.3-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libsmbclient0-debuginfo-3.6.3-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libsmbsharemodes-devel-3.6.3-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libsmbsharemodes0-3.6.3-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libsmbsharemodes0-debuginfo-3.6.3-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libtalloc-devel-2.0.5-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libtalloc2-2.0.5-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libtalloc2-debuginfo-2.0.5-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libtdb-devel-1.2.9-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libtdb1-1.2.9-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libtdb1-debuginfo-1.2.9-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libtevent-devel-0.9.11-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libtevent0-0.9.11-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libtevent0-debuginfo-0.9.11-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libwbclient-devel-3.6.3-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libwbclient0-3.6.3-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libwbclient0-debuginfo-3.6.3-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"samba-3.6.3-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"samba-client-3.6.3-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"samba-client-debuginfo-3.6.3-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"samba-debuginfo-3.6.3-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"samba-debugsource-3.6.3-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"samba-devel-3.6.3-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"samba-krb-printing-3.6.3-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"samba-krb-printing-debuginfo-3.6.3-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"samba-winbind-3.6.3-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"samba-winbind-debuginfo-3.6.3-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libldb1-32bit-1.0.2-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libldb1-debuginfo-32bit-1.0.2-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libsmbclient0-32bit-3.6.3-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libsmbclient0-debuginfo-32bit-3.6.3-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libtalloc2-32bit-2.0.5-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libtalloc2-debuginfo-32bit-2.0.5-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libtdb1-32bit-1.2.9-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libtdb1-debuginfo-32bit-1.2.9-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libtevent0-32bit-0.9.11-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libtevent0-debuginfo-32bit-0.9.11-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libwbclient0-32bit-3.6.3-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libwbclient0-debuginfo-32bit-3.6.3-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"samba-32bit-3.6.3-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"samba-client-32bit-3.6.3-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"samba-client-debuginfo-32bit-3.6.3-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"samba-debuginfo-32bit-3.6.3-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"samba-winbind-32bit-3.6.3-115.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"samba-winbind-debuginfo-32bit-3.6.3-115.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"ldapsmb-1.34b-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libldb-devel-1.0.2-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libldb1-1.0.2-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libldb1-debuginfo-1.0.2-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libnetapi-devel-3.6.3-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libnetapi0-3.6.3-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libnetapi0-debuginfo-3.6.3-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsmbclient-devel-3.6.3-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsmbclient0-3.6.3-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsmbclient0-debuginfo-3.6.3-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsmbsharemodes-devel-3.6.3-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsmbsharemodes0-3.6.3-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsmbsharemodes0-debuginfo-3.6.3-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtalloc-devel-2.0.5-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtalloc2-2.0.5-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtalloc2-debuginfo-2.0.5-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtdb-devel-1.2.9-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtdb1-1.2.9-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtdb1-debuginfo-1.2.9-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtevent-devel-0.9.11-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtevent0-0.9.11-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtevent0-debuginfo-0.9.11-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libwbclient-devel-3.6.3-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libwbclient0-3.6.3-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libwbclient0-debuginfo-3.6.3-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-3.6.3-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-client-3.6.3-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-client-debuginfo-3.6.3-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-debuginfo-3.6.3-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-debugsource-3.6.3-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-devel-3.6.3-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-krb-printing-3.6.3-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-krb-printing-debuginfo-3.6.3-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-winbind-3.6.3-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-winbind-debuginfo-3.6.3-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libldb1-32bit-1.0.2-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libldb1-debuginfo-32bit-1.0.2-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libsmbclient0-32bit-3.6.3-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libsmbclient0-debuginfo-32bit-3.6.3-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libtalloc2-32bit-2.0.5-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libtalloc2-debuginfo-32bit-2.0.5-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libtdb1-32bit-1.2.9-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libtdb1-debuginfo-32bit-1.2.9-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libtevent0-32bit-0.9.11-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libtevent0-debuginfo-32bit-0.9.11-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libwbclient0-32bit-3.6.3-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libwbclient0-debuginfo-32bit-3.6.3-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"samba-32bit-3.6.3-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"samba-client-32bit-3.6.3-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"samba-client-debuginfo-32bit-3.6.3-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"samba-debuginfo-32bit-3.6.3-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"samba-winbind-32bit-3.6.3-34.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"samba-winbind-debuginfo-32bit-3.6.3-34.12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ldapsmb / libldb-devel / libldb1 / libldb1-32bit / etc");
}
