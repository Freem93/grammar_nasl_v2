#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2016-8eb11666aa.
#

include("compat.inc");

if (description)
{
  script_id(92648);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/10/24 13:46:10 $");

  script_cve_id("CVE-2016-5385");
  script_xref(name:"FEDORA", value:"2016-8eb11666aa");

  script_name(english:"Fedora 24 : php (2016-8eb11666aa) (httpoxy)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"21 Jul 2016, **PHP 5.6.24**

**Core:**

  - Fixed bug php#71936 (Segmentation fault destroying
    HTTP_RAW_POST_DATA). (mike dot laspina at gmail dot com,
    Remi)

  - Fixed bug php#72496 (Cannot declare public method with
    signature incompatible with parent private method).
    (Pedro Magalh&atilde;es)

  - Fixed bug php#72138 (Integer Overflow in Length of
    String-typed ZVAL). (Stas)

  - Fixed bug php#72513 (Stack-based buffer overflow
    vulnerability in virtual_file_ex). (loianhtuan at gmail
    dot com)

  - Fixed bug php#72562 (Use After Free in unserialize()
    with Unexpected Session Deserialization). (taoguangchen
    at icloud dot com)

  - Fixed bug php#72573 (HTTP_PROXY is improperly trusted by
    some PHP libraries and applications). (CVE-2016-5385)
    (Stas)

**bz2:**

  - Fixed bug php#72447 (Type Confusion in
    php_bz2_filter_create()). (gogil at stealien dot com).

  - Fixed bug php#72613 (Inadequate error handling in
    bzread()). (Stas)

**EXIF:**

  - Fixed bug php#50845 (exif_read_data() returns corrupted
    exif headers). (Bartosz Dziewo&#x144;ski)

  - Fixed bug php#72603 (Out of bound read in
    exif_process_IFD_in_MAKERNOTE). (Stas)

  - Fixed bug #72618 (NULL pointer Dereference in
    exif_process_user_comment). (Stas)

**Intl:**

  - Fixed bug php#72533 (locale_accept_from_http
    out-of-bounds access). (Stas)

**ODBC:**

  - Fixed bug php#69975 (PHP segfaults when accessing
    nvarchar(max) defined columns)

**OpenSSL:**

  - Fixed bug php#71915 (openssl_random_pseudo_bytes is not
    fork-safe). (Jakub Zelenka)

  - Fixed bug php#72336 (openssl_pkey_new does not fail for
    invalid DSA params). (Jakub Zelenka)

**SNMP:**

  - Fixed bug php#72479 (Use After Free Vulnerability in
    SNMP with GC and unserialize()). (taoguangchen at icloud
    dot com)

**SPL:**

  - Fixed bug php#55701 (GlobIterator throws
    LogicException). (Valentin V&#x102;LCIU)

**SQLite3:**

  - Fixed bug php#70628 (Clearing bindings on a SQLite3
    statement doesn't work). (cmb)

**Streams:**

  - Fixed bug php#72439 (Stream socket with remote address
    leads to a segmentation fault). (Laruence)

**Xmlrpc:**

  - Fixed bug php#72606 (heap-buffer-overflow (write)
    simplestring_addn simplestring.c). (Stas)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2016-8eb11666aa"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:24");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/30");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/01");
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
if (rpm_check(release:"FC24", reference:"php-5.6.24-2.fc24")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
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
