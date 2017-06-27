#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-107.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74882);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/28 18:52:12 $");

  script_cve_id("CVE-2013-0213", "CVE-2013-0214");
  script_osvdb_id(89626, 89627);

  script_name(english:"openSUSE Security Update : samba (openSUSE-SU-2013:0277-1)");
  script_summary(english:"Check for the openSUSE-2013-107 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Samba was updated to 3.6.7 fixing bugs and security issues :

  - The Samba Web Administration Tool (SWAT) in Samba
    versions 3.0.x to 4.0.1 are affected by a cross-site
    request forgery; CVE-2013-0214; (bnc#799641).

  - The Samba Web Administration Tool (SWAT) in Samba
    versions 3.0.x to 4.0.1 could possibly be used in
    clickjacking attacks; CVE-2013-0213; (bnc#800982).

It also contains various other bugfixes merged by our Samba team."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-02/msg00029.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=741623"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=742504"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=755663"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=759731"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=764577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=770056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=779269"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=783384"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=783719"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=786677"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=787983"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=788159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=790741"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=791183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=792340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=799641"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=800982"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE12.1", reference:"ldapsmb-1.34b-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libldb-devel-1.0.2-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libldb1-1.0.2-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libldb1-debuginfo-1.0.2-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libnetapi-devel-3.6.3-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libnetapi0-3.6.3-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libnetapi0-debuginfo-3.6.3-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsmbclient-devel-3.6.3-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsmbclient0-3.6.3-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsmbclient0-debuginfo-3.6.3-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsmbsharemodes-devel-3.6.3-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsmbsharemodes0-3.6.3-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsmbsharemodes0-debuginfo-3.6.3-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtalloc-devel-2.0.5-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtalloc2-2.0.5-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtalloc2-debuginfo-2.0.5-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtdb-devel-1.2.9-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtdb1-1.2.9-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtdb1-debuginfo-1.2.9-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtevent-devel-0.9.11-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtevent0-0.9.11-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtevent0-debuginfo-0.9.11-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libwbclient-devel-3.6.3-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libwbclient0-3.6.3-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libwbclient0-debuginfo-3.6.3-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-3.6.3-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-client-3.6.3-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-client-debuginfo-3.6.3-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-debuginfo-3.6.3-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-debugsource-3.6.3-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-devel-3.6.3-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-krb-printing-3.6.3-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-krb-printing-debuginfo-3.6.3-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-winbind-3.6.3-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-winbind-debuginfo-3.6.3-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libldb1-32bit-1.0.2-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libldb1-debuginfo-32bit-1.0.2-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libsmbclient0-32bit-3.6.3-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libsmbclient0-debuginfo-32bit-3.6.3-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libtalloc2-32bit-2.0.5-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libtalloc2-debuginfo-32bit-2.0.5-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libtdb1-32bit-1.2.9-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libtdb1-debuginfo-32bit-1.2.9-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libtevent0-32bit-0.9.11-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libtevent0-debuginfo-32bit-0.9.11-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libwbclient0-32bit-3.6.3-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libwbclient0-debuginfo-32bit-3.6.3-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"samba-32bit-3.6.3-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"samba-client-32bit-3.6.3-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"samba-client-debuginfo-32bit-3.6.3-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"samba-debuginfo-32bit-3.6.3-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"samba-winbind-32bit-3.6.3-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"samba-winbind-debuginfo-32bit-3.6.3-34.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"ldapsmb-1.34b-48.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libnetapi-devel-3.6.7-48.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libnetapi0-3.6.7-48.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libnetapi0-debuginfo-3.6.7-48.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsmbclient-devel-3.6.7-48.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsmbclient0-3.6.7-48.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsmbclient0-debuginfo-3.6.7-48.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsmbsharemodes-devel-3.6.7-48.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsmbsharemodes0-3.6.7-48.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsmbsharemodes0-debuginfo-3.6.7-48.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libwbclient-devel-3.6.7-48.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libwbclient0-3.6.7-48.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libwbclient0-debuginfo-3.6.7-48.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-3.6.7-48.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-client-3.6.7-48.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-client-debuginfo-3.6.7-48.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-debuginfo-3.6.7-48.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-debugsource-3.6.7-48.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-devel-3.6.7-48.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-krb-printing-3.6.7-48.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-krb-printing-debuginfo-3.6.7-48.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-winbind-3.6.7-48.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"samba-winbind-debuginfo-3.6.7-48.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libsmbclient0-32bit-3.6.7-48.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libsmbclient0-debuginfo-32bit-3.6.7-48.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libwbclient0-32bit-3.6.7-48.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libwbclient0-debuginfo-32bit-3.6.7-48.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"samba-32bit-3.6.7-48.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"samba-client-32bit-3.6.7-48.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"samba-client-debuginfo-32bit-3.6.7-48.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"samba-debuginfo-32bit-3.6.7-48.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"samba-winbind-32bit-3.6.7-48.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"samba-winbind-debuginfo-32bit-3.6.7-48.16.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba");
}
