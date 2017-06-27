#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-435.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75007);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:13 $");

  script_cve_id("CVE-2013-0454");
  script_osvdb_id(91889);

  script_name(english:"openSUSE Security Update : samba (openSUSE-SU-2013:0933-1)");
  script_summary(english:"Check for the openSUSE-2013-435 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This submission supersedes the Samba packages currently available from
http://download.openSUSE.org/pub/opensuse/update/ for openSUSE
versions 12.1 through 12.3.

  - Add support for PFC_FLAG_OBJECT_UUID when parsing
    packets; (bso#9382).

  - Fix 'guest ok', 'force user' and 'force group' for guest
    users; (bso#9746).

  - Fix 'map untrusted to domain' with NTLMv2; (bso#9817).

  - Fix crash bug in Winbind; (bso#9854).

  - Fix panic in nt_printer_publish_ads; (bso#9830)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://download.openSUSE.org/pub/opensuse/update/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-05/msg00029.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-06/msg00070.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=786350"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=792294"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=800782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=802031"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=807334"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=811975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=815994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=7825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9039"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9130"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9139"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9474"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9541"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9568"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9571"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9574"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9585"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9586"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9587"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9625"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9633"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9637"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9646"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9650"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9684"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9686"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9699"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9701"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9724"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9727"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9733"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9736"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9746"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9747"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9766"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9775"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9807"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9809"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9811"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9817"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.samba.org/show_bug.cgi?id=9854"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/14");
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
if (release !~ "^(SUSE12\.1|SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1 / 12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"ldapsmb-1.34b-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libldb-devel-1.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libldb1-1.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libldb1-debuginfo-1.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libnetapi-devel-3.6.3-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libnetapi0-3.6.3-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libnetapi0-debuginfo-3.6.3-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsmbclient-devel-3.6.3-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsmbclient0-3.6.3-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsmbclient0-debuginfo-3.6.3-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsmbsharemodes-devel-3.6.3-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsmbsharemodes0-3.6.3-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsmbsharemodes0-debuginfo-3.6.3-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtalloc-devel-2.0.5-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtalloc2-2.0.5-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtalloc2-debuginfo-2.0.5-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtdb-devel-1.2.9-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtdb1-1.2.9-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtdb1-debuginfo-1.2.9-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtevent-devel-0.9.11-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtevent0-0.9.11-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtevent0-debuginfo-0.9.11-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libwbclient-devel-3.6.3-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libwbclient0-3.6.3-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libwbclient0-debuginfo-3.6.3-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-3.6.3-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-client-3.6.3-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-client-debuginfo-3.6.3-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-debuginfo-3.6.3-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-debugsource-3.6.3-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-devel-3.6.3-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-krb-printing-3.6.3-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-krb-printing-debuginfo-3.6.3-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-winbind-3.6.3-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-winbind-debuginfo-3.6.3-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libldb1-32bit-1.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libldb1-debuginfo-32bit-1.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libsmbclient0-32bit-3.6.3-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libsmbclient0-debuginfo-32bit-3.6.3-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libtalloc2-32bit-2.0.5-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libtalloc2-debuginfo-32bit-2.0.5-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libtdb1-32bit-1.2.9-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libtdb1-debuginfo-32bit-1.2.9-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libtevent0-32bit-0.9.11-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libtevent0-debuginfo-32bit-0.9.11-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libwbclient0-32bit-3.6.3-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libwbclient0-debuginfo-32bit-3.6.3-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"samba-32bit-3.6.3-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"samba-client-32bit-3.6.3-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"samba-client-debuginfo-32bit-3.6.3-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"samba-debuginfo-32bit-3.6.3-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"samba-winbind-32bit-3.6.3-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"samba-winbind-debuginfo-32bit-3.6.3-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"ldapsmb-1.34b-48.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libnetapi-devel-3.6.7-48.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libnetapi0-3.6.7-48.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libnetapi0-debuginfo-3.6.7-48.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsmbclient-devel-3.6.7-48.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsmbclient0-3.6.7-48.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsmbclient0-debuginfo-3.6.7-48.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsmbsharemodes-devel-3.6.7-48.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsmbsharemodes0-3.6.7-48.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsmbsharemodes0-debuginfo-3.6.7-48.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libwbclient-devel-3.6.7-48.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libwbclient0-3.6.7-48.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libwbclient0-debuginfo-3.6.7-48.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-3.6.7-48.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-client-3.6.7-48.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-client-debuginfo-3.6.7-48.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-debuginfo-3.6.7-48.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-debugsource-3.6.7-48.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-devel-3.6.7-48.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-krb-printing-3.6.7-48.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-krb-printing-debuginfo-3.6.7-48.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-winbind-3.6.7-48.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-winbind-debuginfo-3.6.7-48.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libsmbclient0-32bit-3.6.7-48.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libsmbclient0-debuginfo-32bit-3.6.7-48.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libwbclient0-32bit-3.6.7-48.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libwbclient0-debuginfo-32bit-3.6.7-48.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"samba-32bit-3.6.7-48.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"samba-client-32bit-3.6.7-48.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"samba-client-debuginfo-32bit-3.6.7-48.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"samba-debuginfo-32bit-3.6.7-48.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"samba-winbind-32bit-3.6.7-48.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"samba-winbind-debuginfo-32bit-3.6.7-48.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ldapsmb-1.34b-59.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libnetapi-devel-3.6.12-59.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libnetapi0-3.6.12-59.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libnetapi0-debuginfo-3.6.12-59.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsmbclient-devel-3.6.12-59.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsmbclient0-3.6.12-59.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsmbclient0-debuginfo-3.6.12-59.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsmbsharemodes-devel-3.6.12-59.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsmbsharemodes0-3.6.12-59.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsmbsharemodes0-debuginfo-3.6.12-59.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libwbclient-devel-3.6.12-59.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libwbclient0-3.6.12-59.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libwbclient0-debuginfo-3.6.12-59.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-3.6.12-59.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-client-3.6.12-59.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-client-debuginfo-3.6.12-59.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-debuginfo-3.6.12-59.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-debugsource-3.6.12-59.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-devel-3.6.12-59.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-krb-printing-3.6.12-59.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-krb-printing-debuginfo-3.6.12-59.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-winbind-3.6.12-59.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"samba-winbind-debuginfo-3.6.12-59.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libsmbclient0-32bit-3.6.12-59.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libsmbclient0-debuginfo-32bit-3.6.12-59.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libwbclient0-32bit-3.6.12-59.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libwbclient0-debuginfo-32bit-3.6.12-59.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"samba-32bit-3.6.12-59.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"samba-client-32bit-3.6.12-59.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"samba-client-debuginfo-32bit-3.6.12-59.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"samba-debuginfo-32bit-3.6.12-59.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"samba-winbind-32bit-3.6.12-59.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"samba-winbind-debuginfo-32bit-3.6.12-59.5.1") ) flag++;

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
