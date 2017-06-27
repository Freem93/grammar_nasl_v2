#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2016-ec372bddb9.
#

include("compat.inc");

if (description)
{
  script_id(92300);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/10/18 17:03:08 $");

  script_cve_id("CVE-2016-5766", "CVE-2016-5767", "CVE-2016-5768", "CVE-2016-5769", "CVE-2016-5770", "CVE-2016-5771", "CVE-2016-5772");
  script_xref(name:"FEDORA", value:"2016-ec372bddb9");

  script_name(english:"Fedora 24 : php (2016-ec372bddb9)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"23 Jun 2016, **PHP 5.6.23**

**Core:**

  - Fixed bug php#72275 (Integer Overflow in
    json_encode()/json_decode()/json_utf8_to_utf16()).
    (Stas)

  - Fixed bug php#72400 (Integer Overflow in
    addcslashes/addslashes). (Stas)

  - Fixed bug php#72403 (Integer Overflow in Length of
    String-typed ZVAL). (Stas)

**GD:**

  - Fixed bug php#72298 (pass2_no_dither out-of-bounds
    access). (Stas)

  - Fixed bug php#72337 (invalid dimensions can lead to
    crash) (Pierre)

  - Fixed bug php#72339 (Integer Overflow in _gd2GetHeader()
    resulting in heap overflow). (Pierre)

  - Fixed bug php#72407 (NULL pointer Dereference at
    _gdScaleVert). (Stas)

  - Fixed bug php#72446 (Integer Overflow in
    gdImagePaletteToTrueColor() resulting in heap overflow).
    (Pierre)

**Intl:**

  - Fixed bug php#70484 (selectordinal doesn't work with
    named parameters). (Anatol)

**mbstring:**

  - Fixed bug php#72402 (_php_mb_regex_ereg_replace_exec -
    double free). (Stas)

**mcrypt:**

  - Fixed bug php#72455 (Heap Overflow due to integer
    overflows). (Stas)

**Phar:**

  - Fixed bug php#72321 (invalid free in
    phar_extract_file()). (hji at dyntopia dot com)

**SPL:**

  - Fixed bug php#72262 (int/size_t confusion in
    SplFileObject::fread). (Stas)

  - Fixed bug php#72433 (Use After Free Vulnerability in
    PHP's GC algorithm and unserialize). (Dmitry)

**OpenSSL:**

  - Fixed bug php#72140 (segfault after calling
    ERR_free_strings()). (Jakub Zelenka)

**WDDX:**

  - Fixed bug php#72340 (Double Free Courruption in
    wddx_deserialize). (Stas)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2016-ec372bddb9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:24");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/15");
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
if (rpm_check(release:"FC24", reference:"php-5.6.23-1.fc24")) flag++;


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
