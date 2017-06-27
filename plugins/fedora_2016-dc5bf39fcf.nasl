#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2016-dc5bf39fcf.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(94870);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/11/15 14:40:20 $");

  script_xref(name:"FEDORA", value:"2016-dc5bf39fcf");

  script_name(english:"Fedora 25 : php (2016-dc5bf39fcf)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"15 Sep 2016 **PHP version 7.0.11**

**Core:**

  - Fixed bug php#72944 (NULL pointer deref in
    zval_delref_p). (Dmitry)

  - Fixed bug php#72943 (assign_dim on string doesn't reset
    hval). (Laruence)

  - Fixed bug php#72911 (Memleak in
    zend_binary_assign_op_obj_helper). (Laruence)

  - Fixed bug php#72813 (Segfault with __get returned by
    ref). (Laruence)

  - Fixed bug php#72767 (PHP Segfaults when trying to expand
    an infinite operator). (Nikita)

  - Fixed bug php#72854 (PHP Crashes on duplicate destructor
    call). (Nikita)

  - Fixed bug php#72857 (stream_socket_recvfrom read access
    violation). (Anatol)

**Dba:**

  - Fixed bug php#70825 (Cannot fetch multiple values with
    group in ini file). (cmb)

**FTP:**

  - Fixed bug php#70195 (Cannot upload file using ftp_put to
    FTPES with require_ssl_reuse). (Benedict Singer)

**GD:**

  - Fixed bug php#72709 (imagesetstyle() causes OOB read for
    empty $styles). (cmb)

  - Fixed bug php#66005 (imagecopy does not support 1bit
    transparency on truecolor images). (cmb)

  - Fixed bug php#72913 (imagecopy() loses single-color
    transparency on palette images). (cmb)

  - Fixed bug php#68716 (possible resource leaks in
    _php_image_convert()). (cmb)

**iconv:**

  - Fixed bug php#72320 (iconv_substr returns false for
    empty strings). (cmb)

**IMAP:**

  - Fixed bug php#72852 (imap_mail null dereference).
    (Anatol)

**Intl:**

  - Fixed bug php#65732 (grapheme_*() is not Unicode
    compliant on CR LF sequence). (cmb)

  - Fixed bug php#73007 (add locale length check). (Stas)

**Mysqlnd:**

  - Fixed bug php#72293 (Heap overflow in mysqlnd related to
    BIT fields). (Stas)

**Opcache:**

  - Fixed bug php#72949 (Typo in opcache error message).
    (cmb)

**PDO:**

  - Fixed bug php#72788 (Invalid memory access when using
    persistent PDO connection). (Keyur)

  - Fixed bug php#72791 (Memory leak in PDO persistent
    connection handling). (Keyur)

  - Fixed bug php#60665 (call to empty() on NULL result
    using PDO::FETCH_LAZY returns false). (cmb)

**PDO_DBlib:**

  - Implemented stringify 'uniqueidentifier' fields.
    (Alexander Zhuravlev, Adam Baratz)

**PDO_pgsql:**

  - Implemented FR php#72633 (Postgres PDO lastInsertId()
    should work without specifying a sequence). (Pablo
    Santiago S&aacute;nchez, Matteo)

  - Fixed bug php#72759 (Regression in pgo_pgsql). (Anatol)

**Phar:**

  - Fixed bug php#72928 (Out of bound when verify signature
    of zip phar in phar_parse_zipfile). (Stas)

  - Fixed bug php#73035 (Out of bound when verify signature
    of tar phar in phar_parse_tarfile). (Stas)

**Reflection:**

  - Fixed bug php#72846 (getConstant for a array constant
    with constant values returns NULL/NFC/UKNOWN).
    (Laruence)

**Session:**

  - Fixed bug php#72724 (PHP7: session-uploadprogress kills
    httpd). (Nikita)

  - Fixed bug php#72940 (SID always return 'name=ID', even
    if session cookie exist). (Yasuo)

**SimpleXML:**

  - Fixed bug php#72971 (SimpleXML isset/unset do not
    respect namespace). (Nikita)

  - Fixed bug php#72957 (Null coalescing operator doesn't
    behave as expected with SimpleXMLElement). (Nikita)

**SPL:**

  - Fixed bug php#73029 (Missing type check when
    unserializing SplArray). (Stas)

**Standard:**

  - Fixed bug php#55451 (substr_compare NULL length
    interpreted as 0). (Lauri Kentt&auml;)

  - Fixed bug php#72278 (getimagesize returning FALSE on
    valid jpg). (cmb)

  - Fixed bug php#65550 (get_browser() incorrectly parses
    entries with '+' sign). (cmb)

**Streams:**

  - Fixed bug php#72853 (stream_set_blocking doesn't work).
    (Laruence)

  - Fixed bug php#72764 (ftps:// opendir wrapper data
    channel encryption fails with IIS FTP 7.5, 8.5). (vhuk)

  - Fixed bug php#71882 (Negative ftruncate() on
    php://memory exhausts memory). (cmb)

**Sysvshm:**

  - Fixed bug php#72858 (shm_attach null dereference).
    (Anatol)

**XML:**

  - Fixed bug php#72085 (SEGV on unknown address
    zif_xml_parse). (cmb)

  - Fixed bug php#72714 (_xml_startElementHandler()
    segmentation fault). (cmb)

**Wddx:**

  - Fixed bug php#72860 (wddx_deserialize use-after-free).
    (Stas)

  - Fixed bug php#73065 (Out-Of-Bounds Read in
    php_wddx_push_element). (Stas)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2016-dc5bf39fcf"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:25");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/15");
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
if (! ereg(pattern:"^25([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 25", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC25", reference:"php-7.0.11-1.fc25")) flag++;


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
