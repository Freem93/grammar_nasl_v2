#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-251.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(82014);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/24 13:22:29 $");

  script_cve_id("CVE-2014-0190", "CVE-2014-3494", "CVE-2014-8483", "CVE-2014-8600", "CVE-2015-0295");

  script_name(english:"openSUSE Security Update : kdebase4-runtime / kdelibs4 / konversation / etc (openSUSE-2015-251)");
  script_summary(english:"Check for the openSUSE-2015-251 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"KDE and QT were updated to fix security issues and bugs.

The following vulerabilities were fixed :

  - CVE-2014-0190: Malformed GIF files could have crashed QT
    based applications

  - CVE-2015-0295: Malformed BMP files could have crashed QT
    based applications

  - CVE-2014-8600: Multiple cross-site scripting (XSS)
    vulnerabilities in the KDE runtime could have allowed
    remote attackers to insert arbitrary web script or HTML
    via crafted URIs using one of several supported URL
    schemes

  - CVE-2014-8483: A missing size check in the Blowfish ECB
    could have lead to a crash of Konversation or 11 byte
    information leak

  - CVE-2014-3494: The KMail POP3 kioslave accepted invalid
    certifiates and allowed a man-in-the-middle (MITM)
    attack

Additionally, Konversation was updated to 1.5.1 to fix bugs."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=875470"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=883374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=902670"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=905742"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=921999"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdebase4-runtime / kdelibs4 / konversation / etc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase4-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase4-runtime-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase4-runtime-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase4-runtime-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase4-runtime-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4-apidocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4-doc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:konversation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:konversation-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:konversation-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:konversation-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kwebkitpart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kwebkitpart-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kwebkitpart-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kwebkitpart-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkde4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkde4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkde4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkde4-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkde4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdecore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdecore4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdecore4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdecore4-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdecore4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdecore4-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libksuseinstall-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libksuseinstall1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libksuseinstall1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libksuseinstall1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libksuseinstall1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-devel-doc-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-devel-doc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-devel-doc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-linguist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-linguist-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-qt3support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-qt3support-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-qt3support-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-qt3support-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-mysql-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-mysql-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-plugins-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-postgresql-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-postgresql-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-sqlite-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-sqlite-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-unixODBC-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-unixODBC-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-unixODBC-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-x11-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-x11-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:plasma-theme-oxygen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qt4-x11-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qt4-x11-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"kdebase4-runtime-4.11.5-482.6") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdebase4-runtime-branding-upstream-4.11.5-482.6") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdebase4-runtime-debuginfo-4.11.5-482.6") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdebase4-runtime-debugsource-4.11.5-482.6") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdebase4-runtime-devel-4.11.5-482.6") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdelibs4-4.11.5-488.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdelibs4-apidocs-4.11.5-488.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdelibs4-branding-upstream-4.11.5-488.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdelibs4-core-4.11.5-488.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdelibs4-core-debuginfo-4.11.5-488.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdelibs4-debuginfo-4.11.5-488.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdelibs4-debugsource-4.11.5-488.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdelibs4-doc-debuginfo-4.11.5-488.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"konversation-1.5.1-3.4.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"konversation-debuginfo-1.5.1-3.4.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"konversation-debugsource-1.5.1-3.4.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"konversation-lang-1.5.1-3.4.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kwebkitpart-1.3.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kwebkitpart-debuginfo-1.3.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kwebkitpart-debugsource-1.3.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kwebkitpart-lang-1.3.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libkde4-4.11.5-488.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libkde4-debuginfo-4.11.5-488.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libkde4-devel-4.11.5-488.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libkdecore4-4.11.5-488.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libkdecore4-debuginfo-4.11.5-488.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libkdecore4-devel-4.11.5-488.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libkdecore4-devel-debuginfo-4.11.5-488.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libksuseinstall-devel-4.11.5-488.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libksuseinstall1-4.11.5-488.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libksuseinstall1-debuginfo-4.11.5-488.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt4-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt4-debuginfo-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt4-debugsource-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt4-devel-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt4-devel-debuginfo-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt4-devel-doc-data-4.8.5-5.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt4-devel-doc-debuginfo-4.8.5-5.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt4-devel-doc-debugsource-4.8.5-5.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt4-linguist-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt4-linguist-debuginfo-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt4-private-headers-devel-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt4-qt3support-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt4-qt3support-debuginfo-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt4-sql-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt4-sql-debuginfo-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt4-sql-mysql-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt4-sql-mysql-debuginfo-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt4-sql-plugins-debugsource-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt4-sql-postgresql-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt4-sql-postgresql-debuginfo-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt4-sql-sqlite-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt4-sql-sqlite-debuginfo-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt4-sql-unixODBC-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt4-sql-unixODBC-debuginfo-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt4-x11-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt4-x11-debuginfo-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"plasma-theme-oxygen-4.11.5-482.6") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"qt4-x11-tools-4.8.5-5.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"qt4-x11-tools-debuginfo-4.8.5-5.17.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libkde4-32bit-4.11.5-488.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libkde4-debuginfo-32bit-4.11.5-488.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libkdecore4-32bit-4.11.5-488.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libkdecore4-debuginfo-32bit-4.11.5-488.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libksuseinstall1-32bit-4.11.5-488.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libksuseinstall1-debuginfo-32bit-4.11.5-488.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libqt4-32bit-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libqt4-debuginfo-32bit-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libqt4-qt3support-32bit-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libqt4-qt3support-debuginfo-32bit-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libqt4-sql-32bit-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libqt4-sql-debuginfo-32bit-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libqt4-sql-mysql-32bit-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libqt4-sql-mysql-debuginfo-32bit-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libqt4-sql-postgresql-32bit-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libqt4-sql-postgresql-debuginfo-32bit-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libqt4-sql-sqlite-32bit-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libqt4-sql-sqlite-debuginfo-32bit-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libqt4-sql-unixODBC-32bit-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libqt4-sql-unixODBC-debuginfo-32bit-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libqt4-x11-32bit-4.8.5-5.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libqt4-x11-debuginfo-32bit-4.8.5-5.17.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdebase4-runtime / kdebase4-runtime-branding-upstream / etc");
}
