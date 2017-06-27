#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2016-03518b366b.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(94768);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/11/15 14:40:19 $");

  script_xref(name:"FEDORA", value:"2016-03518b366b");

  script_name(english:"Fedora 25 : php (2016-03518b366b)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"18 Aug 2016 **PHP 7.0.10**

**Core:**

  - Fixed bug php#72629 (Caught exception assignment to
    variables ignores references). (Laruence)

  - Fixed bug php#72594 (Calling an earlier instance of an
    included anonymous class fatals). (Laruence)

  - Fixed bug php#72581 (previous property undefined in
    Exception after deserialization). (Laruence)

  - Fixed bug php#72496 (Cannot declare public method with
    signature incompatible with parent private method).
    (Pedro Magalh&atilde;es)

  - Fixed bug php#72024 (microtime() leaks memory).
    (maroszek at gmx dot net)

  - Fixed bug php#71911 (Unable to set --enable-debug on
    building extensions by phpize on Windows). (Yuji
    Uchiyama)

  - Fixed bug causing ClosedGeneratorException being thrown
    into the calling code instead of the Generator yielding
    from. (Bob)

  - Implemented FR php#72614 (Support 'nmake test' on
    building extensions by phpize). (Yuji Uchiyama)

  - Fixed bug php#72641 (phpize (on Windows) ignores
    PHP_PREFIX). (Yuji Uchiyama)

  - Fixed potential segfault in object storage freeing in
    shutdown sequence. (Bob)

  - Fixed bug php#72663 (Create an Unexpected Object and
    Don't Invoke __wakeup() in Deserialization). (Stas)

  - Fixed bug php#72681 (PHP Session Data Injection
    Vulnerability). (Stas)

  - Fixed bug php#72683 (getmxrr broken). (Anatol)

  - Fixed bug php#72742 (memory allocator fails to realloc
    small block to large one). (Stas)

**Bz2:**

  - Fixed bug php#72837 (integer overflow in bzdecompress
    caused heap corruption). (Stas)

**Calendar:**

  - Fixed bug php#67976 (cal_days_month() fails for final
    month of the French calendar). (cmb)

  - Fixed bug php#71894 (AddressSanitizer:
    global-buffer-overflow in zif_cal_from_jd). (cmb)

**COM:**

  - Fixed bug php#72569 (DOTNET/COM array parameters broke
    in PHP7). (Anatol)

**CURL:**

  - Fixed bug php#71709 (curl_setopt segfault with empty
    CURLOPT_HTTPHEADER). (Pierrick)

  - Fixed bug php#71929 (CURLINFO_CERTINFO data parsing
    error). (Pierrick)

  - Fixed bug php#72674 (Heap overflow in curl_escape).
    (Stas)

**DOM:**

  - Fixed bug php#66502 (DOM document dangling reference).
    (Sean Heelan, cmb)

**EXIF:**

  - Fixed bug php#72735 (Samsung picture thumb not read
    (zero size)). (Kalle, Remi)

  - Fixed bug php#72627 (Memory Leakage In
    exif_process_IFD_in_TIFF). (Stas)

**Filter:**

  - Fixed bug php#71745 (FILTER_FLAG_NO_RES_RANGE does not
    cover whole 127.0.0.0/8 range). (bugs dot php dot net at
    majkl578 dot cz)

**FPM:**

  - Fixed bug php#72575 (using --allow-to-run-as-root should
    ignore missing user). (gooh)

**GD:**

  - Fixed bug php#72596 (imagetypes function won't advertise
    WEBP support). (cmb)

  - Fixed bug php#72604 (imagearc() ignores thickness for
    full arcs). (cmb)

  - Fixed bug php#70315 (500 Server Error but page is fully
    rendered). (cmb)

  - Fixed bug php#43828 (broken transparency of imagearc for
    truecolor in blendingmode). (cmb)

  - Fixed bug php#66555 (Always false condition in
    ext/gd/libgd/gdkanji.c). (cmb)

  - Fixed bug php#68712 (suspicious if-else statements).
    (cmb)

  - Fixed bug php#72697 (select_colors write out-of-bounds).
    (Stas)

  - Fixed bug php#72730 (imagegammacorrect allows arbitrary
    write access). (Stas)

**Intl:**

  - Fixed bug php#72639 (Segfault when instantiating class
    that extends IntlCalendar and adds a property).
    (Laruence)

  - Partially fixed php#72506 (idn_to_ascii for UTS #46
    incorrect for long domain names). (cmb)

**mbstring:**

  - Fixed bug php#72691 (mb_ereg_search raises a warning if
    a match zero-width). (cmb)

  - Fixed bug php#72693 (mb_ereg_search increments search
    position when a match zero-width). (cmb)

  - Fixed bug php#72694 (mb_ereg_search_setpos does not
    accept a string's last position). (cmb)

  - Fixed bug php#72710 (`mb_ereg` causes buffer overflow on
    regexp compile error). (ju1ius)

**Mcrypt:**

  - Fixed bug php#72782 (Heap Overflow due to integer
    overflows). (Stas)

**Opcache:**

  - Fixed bug php#72590 (Opcache restart with
    kill_all_lockers does not work). (Keyur)

**PCRE:**

  - Fixed bug php#72688 (preg_match missing group names in
    matches). (cmb)

**PDO_pgsql:**

  - Fixed bug php#70313 (PDO statement fails to throw
    exception). (Matteo)

**Reflection:**

  - Fixed bug php#72222 (ReflectionClass::export doesn't
    handle array constants). (Nikita Nefedov)

**SimpleXML:**

  - Fixed bug php#72588 (Using global var doesn't work while
    accessing SimpleXML element). (Laruence)

**SNMP:**

  - Fixed bug php#72708 (php_snmp_parse_oid integer overflow
    in memory allocation). (djodjo at gmail dot com)

**SPL:**

  - Fixed bug php#55701 (GlobIterator throws
    LogicException). (Valentin V&#x102;LCIU)

  - Fixed bug php#72646 (SplFileObject::getCsvControl does
    not return the escape character). (cmb)

  - Fixed bug php#72684 (AppendIterator segfault with closed
    generator). (Pierrick)

**SQLite3:**

  - Fixed bug php#72668 (Spurious warning when exception is
    thrown in user defined function). (Laruence)

  - Fixed bug php#72571 (SQLite3::bindValue,
    SQLite3::bindParam crash). (Laruence)

  - Implemented FR php#72653 (SQLite should allow opening
    with empty filename). (cmb)

  - Updated to SQLite3 3.13.0. (cmb)

**Standard:**

  - Fixed bug php#72622 (array_walk +
    array_replace_recursive create references from nothing).
    (Laruence)

  - Fixed bug php#72152 (base64_decode $strict fails to
    detect null byte). (Lauri Kentt&auml;)

  - Fixed bug php#72263 (base64_decode skips a character
    after padding in strict mode). (Lauri Kentt&auml;)

  - Fixed bug php#72264 (base64_decode $strict fails with
    whitespace between padding). (Lauri Kentt&auml;)

  - Fixed bug php#72330 (CSV fields incorrectly split if
    escape char followed by UTF chars). (cmb)

**Streams:**

  - Fixed bug php#41021 (Problems with the ftps wrapper).
    (vhuk)

  - Fixed bug php#54431 (opendir() does not work with
    ftps:// wrapper). (vhuk)

  - Fixed bug php#72667 (opendir() with ftp:// attempts to
    open data stream for non-existent directories). (vhuk)

  - Fixed bug php#72771 (ftps:// wrapper is vulnerable to
    protocol downgrade attack). (Stas)

**XMLRPC:**

  - Fixed bug php#72647 (xmlrpc_encode() unexpected output
    after referencing array elements). (Laruence)

**Wddx:**

  - Fixed bug php#72564 (boolean always deserialized as
    'true') (Remi)

  - Fixed bug php#72142 (WDDX Packet Injection Vulnerability
    in wddx_serialize_value()). (Taoguang Chen)

  - Fixed bug php#72749 (wddx_deserialize allows illegal
    memory access) (Stas)

  - Fixed bug php#72750 (wddx_deserialize null dereference).
    (Stas)

  - Fixed bug php#72790 (wddx_deserialize null dereference
    with invalid xml). (Stas)

  - Fixed bug php#72771 (ftps:// wrapper is vulnerable to
    protocol downgrade attack). (Stas)

**XMLRPC:**

  - Fixed bug php#72647 (xmlrpc_encode() unexpected output
    after referencing array elements). (Laruence)

**Wddx:**

  - Fixed bug php#72564 (boolean always deserialized as
    'true') (Remi)

  - Fixed bug php#72142 (WDDX Packet Injection Vulnerability
    in wddx_serialize_value()). (Taoguang Chen)

  - Fixed bug php#72749 (wddx_deserialize allows illegal
    memory access) (Stas)

  - Fixed bug php#72750 (wddx_deserialize null dereference).
    (Stas)

  - Fixed bug php#72790 (wddx_deserialize null dereference
    with invalid xml). (Stas)

  - Fixed bug php#72799 (wddx_deserialize null dereference
    in php_wddx_pop_element). (Stas)

**Zip:**

  - Fixed bug php#72660 (NULL pointer dereference in
    zend_virtual_cwd). (Laruence)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2016-03518b366b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:25");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/05");
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
if (rpm_check(release:"FC25", reference:"php-7.0.10-1.fc25")) flag++;


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
