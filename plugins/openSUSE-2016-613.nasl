#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-613.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(89093);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2016/10/13 14:37:12 $");

  script_cve_id("CVE-2016-4342", "CVE-2016-4343", "CVE-2016-4346", "CVE-2016-4537", "CVE-2016-4538", "CVE-2016-4539", "CVE-2016-4540", "CVE-2016-4541", "CVE-2016-4542", "CVE-2016-4543", "CVE-2016-4544");

  script_name(english:"openSUSE Security Update : libqt5-qtbase (openSUSE-2016-613)");
  script_summary(english:"Check for the openSUSE-2016-613 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libqt5-qtbase fixes the following issues :

  - boo#865241: disable RC4 based ciphers which are now
    considered insecure

The following non-security bugs were fixed :

  - boo#957006: dolphin freeze when opening a folder
    containing symlinks to special files"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=865241"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957006"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=977991"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=977992"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=977994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978828"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978830"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libqt5-qtbase packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-mod_php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-mod_php5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Bootstrap-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Bootstrap-devel-static-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Concurrent-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Concurrent-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Concurrent5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Concurrent5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Concurrent5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Concurrent5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Core-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Core-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Core-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Core5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Core5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Core5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Core5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus-devel-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Gui-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Gui-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Gui-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Gui5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Gui5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Gui5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Gui5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Network-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Network-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Network-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Network5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Network5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Network5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Network5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGL-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGL-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGL-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGL5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGL5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGL5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGL5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGLExtensions-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGLExtensions-devel-static-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PlatformHeaders-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PlatformSupport-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PlatformSupport-devel-static-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PlatformSupport-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PrintSupport-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PrintSupport-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PrintSupport-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PrintSupport5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PrintSupport5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PrintSupport5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PrintSupport5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-mysql-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-mysql-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-postgresql-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-postgresql-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-sqlite-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-sqlite-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-unixODBC-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-unixODBC-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-unixODBC-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Test-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Test-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Test-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Test5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Test5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Test5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Test5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Widgets-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Widgets-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Widgets-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Widgets5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Widgets5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Widgets5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Widgets5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Xml-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Xml-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Xml5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Xml5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Xml5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Xml5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-common-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-common-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-doc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-examples-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-examples-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-examples-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-platformtheme-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-platformtheme-gtk2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-bcmath-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-bz2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-calendar-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-ctype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-ctype-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-dba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-dom-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-enchant-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-exif-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-fastcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-fastcgi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-fileinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-fileinfo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-firebird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-firebird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-fpm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-ftp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-gd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-gettext-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-gmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-iconv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-iconv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-imap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-intl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-json-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mbstring-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mcrypt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mssql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mssql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-odbc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-opcache-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pcntl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pcntl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pdo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-phar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-phar-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-posix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-posix-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pspell-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-readline-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-shmop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-shmop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-snmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-soap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sockets-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-suhosin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-suhosin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sysvmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sysvmsg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sysvsem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sysvsem-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sysvshm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sysvshm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-tidy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-tokenizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-tokenizer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-wddx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-wddx-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-xmlreader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-xmlreader-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-xmlrpc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-xmlwriter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-xmlwriter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-xsl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-zip-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-zlib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"apache2-mod_php5-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-mod_php5-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-bcmath-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-bcmath-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-bz2-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-bz2-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-calendar-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-calendar-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-ctype-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-ctype-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-curl-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-curl-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-dba-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-dba-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-debugsource-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-devel-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-dom-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-dom-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-enchant-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-enchant-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-exif-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-exif-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-fastcgi-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-fastcgi-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-fileinfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-fileinfo-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-firebird-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-firebird-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-fpm-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-fpm-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-ftp-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-ftp-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-gd-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-gd-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-gettext-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-gettext-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-gmp-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-gmp-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-iconv-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-iconv-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-imap-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-imap-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-intl-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-intl-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-json-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-json-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-ldap-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-ldap-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-mbstring-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-mbstring-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-mcrypt-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-mcrypt-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-mssql-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-mssql-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-mysql-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-mysql-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-odbc-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-odbc-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-opcache-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-opcache-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-openssl-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-openssl-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-pcntl-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-pcntl-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-pdo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-pdo-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-pear-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-pgsql-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-pgsql-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-phar-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-phar-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-posix-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-posix-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-pspell-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-pspell-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-readline-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-readline-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-shmop-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-shmop-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-snmp-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-snmp-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-soap-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-soap-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-sockets-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-sockets-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-sqlite-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-sqlite-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-suhosin-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-suhosin-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-sysvmsg-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-sysvmsg-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-sysvsem-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-sysvsem-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-sysvshm-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-sysvshm-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-tidy-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-tidy-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-tokenizer-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-tokenizer-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-wddx-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-wddx-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-xmlreader-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-xmlreader-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-xmlrpc-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-xmlrpc-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-xmlwriter-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-xmlwriter-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-xsl-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-xsl-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-zip-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-zip-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-zlib-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-zlib-debuginfo-5.6.1-61.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Bootstrap-devel-static-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Concurrent-devel-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Concurrent5-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Concurrent5-debuginfo-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Core-devel-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Core-private-headers-devel-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Core5-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Core5-debuginfo-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5DBus-devel-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5DBus-devel-debuginfo-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5DBus-private-headers-devel-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5DBus5-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5DBus5-debuginfo-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Gui-devel-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Gui-private-headers-devel-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Gui5-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Gui5-debuginfo-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Network-devel-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Network-private-headers-devel-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Network5-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Network5-debuginfo-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5OpenGL-devel-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5OpenGL-private-headers-devel-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5OpenGL5-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5OpenGL5-debuginfo-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5OpenGLExtensions-devel-static-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5PlatformHeaders-devel-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5PlatformSupport-devel-static-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5PlatformSupport-private-headers-devel-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5PrintSupport-devel-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5PrintSupport-private-headers-devel-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5PrintSupport5-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5PrintSupport5-debuginfo-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Sql-devel-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Sql-private-headers-devel-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Sql5-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Sql5-debuginfo-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Sql5-mysql-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Sql5-mysql-debuginfo-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Sql5-postgresql-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Sql5-postgresql-debuginfo-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Sql5-sqlite-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Sql5-sqlite-debuginfo-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Sql5-unixODBC-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Sql5-unixODBC-debuginfo-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Test-devel-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Test-private-headers-devel-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Test5-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Test5-debuginfo-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Widgets-devel-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Widgets-private-headers-devel-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Widgets5-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Widgets5-debuginfo-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Xml-devel-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Xml5-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libQt5Xml5-debuginfo-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libqt5-qtbase-common-devel-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libqt5-qtbase-common-devel-debuginfo-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libqt5-qtbase-debugsource-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libqt5-qtbase-devel-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libqt5-qtbase-doc-debuginfo-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libqt5-qtbase-examples-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libqt5-qtbase-examples-debuginfo-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libqt5-qtbase-platformtheme-gtk2-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libqt5-qtbase-platformtheme-gtk2-debuginfo-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libqt5-qtbase-private-headers-devel-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5Bootstrap-devel-static-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5Concurrent-devel-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5Concurrent5-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5Concurrent5-debuginfo-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5Core-devel-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5Core5-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5Core5-debuginfo-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5DBus-devel-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5DBus-devel-debuginfo-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5DBus5-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5DBus5-debuginfo-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5Gui-devel-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5Gui5-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5Gui5-debuginfo-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5Network-devel-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5Network5-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5Network5-debuginfo-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5OpenGL-devel-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5OpenGL5-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5OpenGL5-debuginfo-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5OpenGLExtensions-devel-static-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5PlatformSupport-devel-static-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5PrintSupport-devel-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5PrintSupport5-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5PrintSupport5-debuginfo-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5Sql-devel-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5Sql5-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5Sql5-debuginfo-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5Sql5-mysql-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5Sql5-mysql-debuginfo-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5Sql5-postgresql-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5Sql5-postgresql-debuginfo-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5Sql5-sqlite-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5Sql5-sqlite-debuginfo-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5Sql5-unixODBC-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5Sql5-unixODBC-debuginfo-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5Test-devel-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5Test5-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5Test5-debuginfo-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5Widgets-devel-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5Widgets5-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5Widgets5-debuginfo-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5Xml-devel-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5Xml5-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libQt5Xml5-debuginfo-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libqt5-qtbase-examples-32bit-5.5.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libqt5-qtbase-examples-debuginfo-32bit-5.5.1-10.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2-mod_php5 / apache2-mod_php5-debuginfo / php5 / php5-bcmath / etc");
}
