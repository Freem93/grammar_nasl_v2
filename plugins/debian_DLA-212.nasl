#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-212-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83144);
  script_version("$Revision: 2.10 $");
  script_cvs_date("$Date: 2016/05/19 17:45:43 $");

  script_cve_id("CVE-2014-9705", "CVE-2015-0232", "CVE-2015-2301", "CVE-2015-2331", "CVE-2015-2783", "CVE-2015-2787", "CVE-2015-3329", "CVE-2015-3330");
  script_bugtraq_id(72541, 73031, 73037, 73182, 73431, 74204, 74239, 74240);
  script_osvdb_id(117467, 118582, 119650, 119693, 119774, 120925, 120930, 120938);

  script_name(english:"Debian DLA-212-1 : php5 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2014-9705 Heap-based buffer overflow in the
enchant_broker_request_dict function in ext/enchant/enchant.c in PHP
before 5.4.38, 5.5.x before 5.5.22, and 5.6.x before 5.6.6 allows
remote attackers to execute arbitrary code via vectors that trigger
creation of multiple dictionaries.

CVE-2015-0232 The exif_process_unicode function in ext/exif/exif.c in
PHP before 5.4.37, 5.5.x before 5.5.21, and 5.6.x before 5.6.5 allows
remote attackers to execute arbitrary code or cause a denial of
service (uninitialized pointer free and application crash) via crafted
EXIF data in a JPEG image.

CVE-2015-2301 Use-after-free vulnerability in the phar_rename_archive
function in phar_object.c in PHP before 5.5.22 and 5.6.x before 5.6.6
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors that trigger an attempted
renaming of a Phar archive to the name of an existing file.

CVE-2015-2331 Integer overflow in the _zip_cdir_new function in
zip_dirent.c in libzip 0.11.2 and earlier, as used in the ZIP
extension in PHP before 5.4.39, 5.5.x before 5.5.23, and 5.6.x before
5.6.7 and other products, allows remote attackers to cause a denial of
service (application crash) or possibly execute arbitrary code via a
ZIP archive that contains many entries, leading to a heap-based buffer
overflow.

CVE-2015-2783 Buffer Over-read in unserialize when parsing Phar

CVE-2015-2787 Use-after-free vulnerability in the process_nested_data
function in ext/standard/var_unserializer.re in PHP before 5.4.39,
5.5.x before 5.5.23, and 5.6.x before 5.6.7 allows remote attackers to
execute arbitrary code via a crafted unserialize call that leverages
use of the unset function within an __wakeup function, a related issue
to CVE-2015-0231.

CVE-2015-3329 Buffer Overflow when parsing tar/zip/phar in
phar_set_inode)

CVE-2015-3330 PHP potential remote code execution with apache 2.4
apache2handler

CVE-2015-temp-68819 denial of service when processing a crafted file
with Fileinfo

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/04/msg00025.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/php5"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-php5filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-interbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-xsl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"6.0", prefix:"libapache2-mod-php5", reference:"5.3.3.1-7+squeeze26")) flag++;
if (deb_check(release:"6.0", prefix:"libapache2-mod-php5filter", reference:"5.3.3.1-7+squeeze26")) flag++;
if (deb_check(release:"6.0", prefix:"php-pear", reference:"5.3.3.1-7+squeeze26")) flag++;
if (deb_check(release:"6.0", prefix:"php5", reference:"5.3.3.1-7+squeeze26")) flag++;
if (deb_check(release:"6.0", prefix:"php5-cgi", reference:"5.3.3.1-7+squeeze26")) flag++;
if (deb_check(release:"6.0", prefix:"php5-cli", reference:"5.3.3.1-7+squeeze26")) flag++;
if (deb_check(release:"6.0", prefix:"php5-common", reference:"5.3.3.1-7+squeeze26")) flag++;
if (deb_check(release:"6.0", prefix:"php5-curl", reference:"5.3.3.1-7+squeeze26")) flag++;
if (deb_check(release:"6.0", prefix:"php5-dbg", reference:"5.3.3.1-7+squeeze26")) flag++;
if (deb_check(release:"6.0", prefix:"php5-dev", reference:"5.3.3.1-7+squeeze26")) flag++;
if (deb_check(release:"6.0", prefix:"php5-enchant", reference:"5.3.3.1-7+squeeze26")) flag++;
if (deb_check(release:"6.0", prefix:"php5-gd", reference:"5.3.3.1-7+squeeze26")) flag++;
if (deb_check(release:"6.0", prefix:"php5-gmp", reference:"5.3.3.1-7+squeeze26")) flag++;
if (deb_check(release:"6.0", prefix:"php5-imap", reference:"5.3.3.1-7+squeeze26")) flag++;
if (deb_check(release:"6.0", prefix:"php5-interbase", reference:"5.3.3.1-7+squeeze26")) flag++;
if (deb_check(release:"6.0", prefix:"php5-intl", reference:"5.3.3.1-7+squeeze26")) flag++;
if (deb_check(release:"6.0", prefix:"php5-ldap", reference:"5.3.3.1-7+squeeze26")) flag++;
if (deb_check(release:"6.0", prefix:"php5-mcrypt", reference:"5.3.3.1-7+squeeze26")) flag++;
if (deb_check(release:"6.0", prefix:"php5-mysql", reference:"5.3.3.1-7+squeeze26")) flag++;
if (deb_check(release:"6.0", prefix:"php5-odbc", reference:"5.3.3.1-7+squeeze26")) flag++;
if (deb_check(release:"6.0", prefix:"php5-pgsql", reference:"5.3.3.1-7+squeeze26")) flag++;
if (deb_check(release:"6.0", prefix:"php5-pspell", reference:"5.3.3.1-7+squeeze26")) flag++;
if (deb_check(release:"6.0", prefix:"php5-recode", reference:"5.3.3.1-7+squeeze26")) flag++;
if (deb_check(release:"6.0", prefix:"php5-snmp", reference:"5.3.3.1-7+squeeze26")) flag++;
if (deb_check(release:"6.0", prefix:"php5-sqlite", reference:"5.3.3.1-7+squeeze26")) flag++;
if (deb_check(release:"6.0", prefix:"php5-sybase", reference:"5.3.3.1-7+squeeze26")) flag++;
if (deb_check(release:"6.0", prefix:"php5-tidy", reference:"5.3.3.1-7+squeeze26")) flag++;
if (deb_check(release:"6.0", prefix:"php5-xmlrpc", reference:"5.3.3.1-7+squeeze26")) flag++;
if (deb_check(release:"6.0", prefix:"php5-xsl", reference:"5.3.3.1-7+squeeze26")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
