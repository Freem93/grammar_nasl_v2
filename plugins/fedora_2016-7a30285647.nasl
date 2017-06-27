#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2016-7a30285647.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(94209);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/10/24 13:56:00 $");

  script_xref(name:"FEDORA", value:"2016-7a30285647");

  script_name(english:"Fedora 24 : php (2016-7a30285647)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"13 Oct 2016 - **PHP version 5.6.27**

**Core:**

  - Fixed bug php#73025 (Heap Buffer Overflow in
    virtual_popen of zend_virtual_cwd.c). (cmb)

  - Fixed bug php#73058 (crypt broken when salt is 'too'
    long). (Anatol)

  - Fixed bug php#72703 (Out of bounds global memory read in
    BF_crypt triggered by password_verify). (Anatol)

  - Fixed bug php#73189 (Memcpy negative size parameter
    php_resolve_path). (Stas)

  - Fixed bug php#73147 (Use After Free in unserialize()).
    (Stas)

**BCmath:**

  - Fixed bug php#73190 (memcpy negative parameter
    _bc_new_num_ex). (Stas)

**DOM:**

  - Fixed bug php#73150 (missing NULL check in
    dom_document_save_html). (Stas)

**Ereg:**

  - Fixed bug php#73284 (heap overflow in php_ereg_replace
    function). (Stas)

**Filter:**

  - Fixed bug php#72972 (Bad filter for the flags
    FILTER_FLAG_NO_RES_RANGE and FILTER_FLAG_NO_PRIV_RANGE).
    (julien)

  - Fixed bug php#67167 (Wrong return value from
    FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE).
    (levim, cmb)

  - Fixed bug php#73054 (default option ignored when object
    passed to int filter). (cmb)

**GD:**

  - Fixed bug php#67325 (imagetruecolortopalette: white is
    duplicated in palette). (cmb)

  - Fixed bug php#50194 (imagettftext broken on transparent
    background w/o alphablending). (cmb)

  - Fixed bug php#73003 (Integer Overflow in gdImageWebpCtx
    of gd_webp.c). (trylab, cmb)

  - Fixed bug php#53504 (imagettfbbox gives incorrect values
    for bounding box). (Mark Plomer, cmb)

  - Fixed bug php#73157 (imagegd2() ignores 3rd param if 4
    are given). (cmb)

  - Fixed bug php#73155 (imagegd2() writes wrong chunk sizes
    on boundaries). (cmb)

  - Fixed bug php#73159 (imagegd2(): unrecognized formats
    may result in corrupted files). (cmb)

  - Fixed bug php#73161 (imagecreatefromgd2() may leak
    memory). (cmb)

**Intl:**

  - Fixed bug php#73218 (add mitigation for ICU int
    overflow). (Stas)

**Imap:**

  - Fixed bug php#73208 (integer overflow in imap_8bit
    caused heap corruption). (Stas)

**Mbstring:**

  - Fixed bug php#72994 (mbc_to_code() out of bounds read).
    (Laruence, cmb)

  - Fixed bug php#66964 (mb_convert_variables() cannot
    detect recursion). (Yasuo)

  - Fixed bug php#72992 (mbstring.internal_encoding doesn't
    inherit default_charset). (Yasuo)

  - Fixed bug php#73082 (string length overflow in
    mb_encode_* function). (Stas)

**PCRE:**

  - Fixed bug php#73174 (heap overflow in
    php_pcre_replace_impl). (Stas)

**Opcache:**

  - Fixed bug php#72590 (Opcache restart with
    kill_all_lockers does not work). (Keyur) (julien
    backport)

**OpenSSL:**

  - Fixed bug php#73072 (Invalid path SNI_server_certs
    causes segfault). (Jakub Zelenka)

  - Fixed bug php#73275 (crash in openssl_encrypt function).
    (Stas)

  - Fixed bug php#73276 (crash in
    openssl_random_pseudo_bytes function). (Stas)

**Session:**

  - Fixed bug php#68015 (Session does not report invalid uid
    for files save handler). (Yasuo)

  - Fixed bug php#73100 (session_destroy null dereference in
    ps_files_path_create). (cmb)

**SimpleXML:**

  - Fixed bug php#73293 (NULL pointer dereference in
    SimpleXMLElement::asXML()). (Stas)

**SPL:**

  - Fixed bug php#73073 (CachingIterator null dereference
    when convert to string). (Stas)

**Standard:**

  - Fixed bug php#73240 (Write out of bounds at
    number_format). (Stas)

  - Fixed bug php#73017 (memory corruption in wordwrap
    function). (Stas)

**Stream:**

  - Fixed bug php#73069 (readfile() mangles files larger
    than 2G). (Laruence)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2016-7a30285647"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:24");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/24");
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
if (rpm_check(release:"FC24", reference:"php-5.6.27-1.fc24")) flag++;


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
