#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2016-62fc05fd68.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(93726);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/10/25 16:58:35 $");

  script_cve_id("CVE-2016-7411", "CVE-2016-7412", "CVE-2016-7413", "CVE-2016-7414", "CVE-2016-7416", "CVE-2016-7417", "CVE-2016-7418");
  script_xref(name:"FEDORA", value:"2016-62fc05fd68");

  script_name(english:"Fedora 24 : php (2016-62fc05fd68)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"15 Sep 2016 **PHP version 5.6.26**

**Core:**

  - Fixed bug php#72907 (NULL pointer deref, segfault in
    gc_remove_zval_from_buffer (zend_gc.c:260)). (Laruence)

**Dba:**

  - Fixed bug php#71514 (Bad dba_replace condition because
    of wrong API usage). (cmb)

  - Fixed bug php#70825 (Cannot fetch multiple values with
    group in ini file). (cmb)

**EXIF:**

  - Fixed bug php#72926 (Uninitialized Thumbail Data Leads
    To Memory Leakage in exif_process_IFD_in_TIFF). (Stas)

**FTP:**

  - Fixed bug php#70195 (Cannot upload file using ftp_put to
    FTPES with require_ssl_reuse). (Benedict Singer)

**GD:**

  - Fixed bug php#66005 (imagecopy does not support 1bit
    transparency on truecolor images). (cmb)

  - Fixed bug php#72913 (imagecopy() loses single-color
    transparency on palette images). (cmb)

  - Fixed bug php#68716 (possible resource leaks in
    _php_image_convert()). (cmb)

**Intl:**

  - Fixed bug php#73007 (add locale length check). (Stas)

**JSON:**

  - Fixed bug php#72787 (json_decode reads out of bounds).
    (Jakub Zelenka)

**mbstring:**

  - Fixed bug php#66797 (mb_substr only takes 32-bit signed
    integer). (cmb)

  - Fixed bug php#72910 (Out of bounds heap read in
    mbc_to_code() / triggered by mb_ereg_match()). (Stas)

**MSSQL:**

  - Fixed bug php#72039 (Use of uninitialised value on
    mssql_guid_string). (Kalle)

**Mysqlnd:**

  - Fixed bug php#72293 (Heap overflow in mysqlnd related to
    BIT fields). (Stas)

**Phar:**

  - Fixed bug php#72928 (Out of bound when verify signature
    of zip phar in phar_parse_zipfile). (Stas)

  - Fixed bug php#73035 (Out of bound when verify signature
    of tar phar in phar_parse_tarfile). (Stas)

**PDO:**

  - Fixed bug php#60665 (call to empty() on NULL result
    using PDO::FETCH_LAZY returns false). (cmb)

**PDO_pgsql:**

  - Implemented FR php#72633 (Postgres PDO lastInsertId()
    should work without specifying a sequence). (Pablo
    Santiago S&aacute;nchez, Matteo)

  - Fixed bug php#72759 (Regression in pgo_pgsql). (Anatol)

**SPL:**

  - Fixed bug php#73029 (Missing type check when
    unserializing SplArray). (Stas)

**Standard:**

  - Fixed bug php#72823 (strtr out-of-bound access). (cmb)

  - Fixed bug php#72278 (getimagesize returning FALSE on
    valid jpg). (cmb)

  - Fixed bug php#65550 (get_browser() incorrectly parses
    entries with '+' sign). (cmb)

  - Fixed bug php#71882 (Negative ftruncate() on
    php://memory exhausts memory). (cmb)

  - Fixed bug php#73011 (integer overflow in fgets cause
    heap corruption). (Stas)

  - Fixed bug php#73017 (memory corruption in wordwrap
    function). (Stas)

  - Fixed bug php#73045 (integer overflow in fgetcsv caused
    heap corruption). (Stas)

  - Fixed bug php#73052 (Memory Corruption in During
    Deserialized-object Destruction) (Stas)

**Streams:**

  - Fixed bug php#72853 (stream_set_blocking doesn't work).
    (Laruence)

**Wddx:**

  - Fixed bug php#72860 (wddx_deserialize use-after-free).
    (Stas)

  - Fixed bug php#73065 (Out-Of-Bounds Read in
    php_wddx_push_element). (Stas)

**XML:**

  - Fixed bug php#72085 (SEGV on unknown address
    zif_xml_parse). (cmb)

  - Fixed bug php#72927 (integer overflow in
    xml_utf8_encode). (Stas)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2016-62fc05fd68"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:24");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^24([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 24", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC24", reference:"php-5.6.26-1.fc24")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php");
}
