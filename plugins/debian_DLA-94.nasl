#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-94-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82239);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/12/02 20:16:13 $");

  script_cve_id("CVE-2014-3668", "CVE-2014-3669", "CVE-2014-3670", "CVE-2014-3710");
  script_bugtraq_id(70611, 70665, 70666, 70807);
  script_osvdb_id(113421, 113422, 113423, 113614);

  script_name(english:"Debian DLA-94-1 : php5 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2014-3668

Fix bug #68027 - fix date parsing in XMLRPC lib

CVE-2014-3669

Fix bug #68044: Integer overflow in unserialize() (32-bits only)

CVE-2014-3670

Fix bug #68113 (Heap corruption in exif_thumbnail())

CVE-2014-3710

Fix bug #68283: fileinfo: out-of-bounds read in elf note headers

Additional bugfix

Fix null byte handling in LDAP bindings in ldap-fix.patch

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2014/11/msg00013.html"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libapache2-mod-php5", reference:"5.3.3-7+squeeze23")) flag++;
if (deb_check(release:"6.0", prefix:"libapache2-mod-php5filter", reference:"5.3.3-7+squeeze23")) flag++;
if (deb_check(release:"6.0", prefix:"php-pear", reference:"5.3.3-7+squeeze23")) flag++;
if (deb_check(release:"6.0", prefix:"php5", reference:"5.3.3-7+squeeze23")) flag++;
if (deb_check(release:"6.0", prefix:"php5-cgi", reference:"5.3.3-7+squeeze23")) flag++;
if (deb_check(release:"6.0", prefix:"php5-cli", reference:"5.3.3-7+squeeze23")) flag++;
if (deb_check(release:"6.0", prefix:"php5-common", reference:"5.3.3-7+squeeze23")) flag++;
if (deb_check(release:"6.0", prefix:"php5-curl", reference:"5.3.3-7+squeeze23")) flag++;
if (deb_check(release:"6.0", prefix:"php5-dbg", reference:"5.3.3-7+squeeze23")) flag++;
if (deb_check(release:"6.0", prefix:"php5-dev", reference:"5.3.3-7+squeeze23")) flag++;
if (deb_check(release:"6.0", prefix:"php5-enchant", reference:"5.3.3-7+squeeze23")) flag++;
if (deb_check(release:"6.0", prefix:"php5-gd", reference:"5.3.3-7+squeeze23")) flag++;
if (deb_check(release:"6.0", prefix:"php5-gmp", reference:"5.3.3-7+squeeze23")) flag++;
if (deb_check(release:"6.0", prefix:"php5-imap", reference:"5.3.3-7+squeeze23")) flag++;
if (deb_check(release:"6.0", prefix:"php5-interbase", reference:"5.3.3-7+squeeze23")) flag++;
if (deb_check(release:"6.0", prefix:"php5-intl", reference:"5.3.3-7+squeeze23")) flag++;
if (deb_check(release:"6.0", prefix:"php5-ldap", reference:"5.3.3-7+squeeze23")) flag++;
if (deb_check(release:"6.0", prefix:"php5-mcrypt", reference:"5.3.3-7+squeeze23")) flag++;
if (deb_check(release:"6.0", prefix:"php5-mysql", reference:"5.3.3-7+squeeze23")) flag++;
if (deb_check(release:"6.0", prefix:"php5-odbc", reference:"5.3.3-7+squeeze23")) flag++;
if (deb_check(release:"6.0", prefix:"php5-pgsql", reference:"5.3.3-7+squeeze23")) flag++;
if (deb_check(release:"6.0", prefix:"php5-pspell", reference:"5.3.3-7+squeeze23")) flag++;
if (deb_check(release:"6.0", prefix:"php5-recode", reference:"5.3.3-7+squeeze23")) flag++;
if (deb_check(release:"6.0", prefix:"php5-snmp", reference:"5.3.3-7+squeeze23")) flag++;
if (deb_check(release:"6.0", prefix:"php5-sqlite", reference:"5.3.3-7+squeeze23")) flag++;
if (deb_check(release:"6.0", prefix:"php5-sybase", reference:"5.3.3-7+squeeze23")) flag++;
if (deb_check(release:"6.0", prefix:"php5-tidy", reference:"5.3.3-7+squeeze23")) flag++;
if (deb_check(release:"6.0", prefix:"php5-xmlrpc", reference:"5.3.3-7+squeeze23")) flag++;
if (deb_check(release:"6.0", prefix:"php5-xsl", reference:"5.3.3-7+squeeze23")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
