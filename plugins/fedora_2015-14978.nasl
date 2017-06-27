#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-14978.
#

include("compat.inc");

if (description)
{
  script_id(86030);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/10/18 16:42:52 $");

  script_cve_id("CVE-2015-6834", "CVE-2015-6835", "CVE-2015-6836", "CVE-2015-6837", "CVE-2015-6838");
  script_xref(name:"FEDORA", value:"2015-14978");

  script_name(english:"Fedora 23 : php-5.6.13-1.fc23 (2015-14978)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"03 Sep 2015, **PHP 5.6.13** **Core:** * Fixed bug #69900 (Too long
timeout on pipes). (Anatol) * Fixed bug #69487 (SAPI may truncate POST
data). (cmb) * Fixed bug #70198 (Checking liveness does not work as
expected). (Shafreeck Sea, Anatol Belski) * Fixed bug #70172 (Use
After Free Vulnerability in unserialize()). (Stas) * Fixed bug #70219
(Use after free vulnerability in session deserializer). (taoguangchen
at icloud dot com) **CLI server:** * Fixed bug #66606 (Sets
HTTP_CONTENT_TYPE but not CONTENT_TYPE). (wusuopu, cmb) * Fixed bug
#70264 (CLI server directory traversal). (cmb) **Date:** * Fixed bug
#70266 (DateInterval::__construct.interval_spec is not supposed to be
optional). (cmb)

  - Fixed bug #70277 (new DateTimeZone($foo) is ignoring
    text after null byte). (cmb) **EXIF:** * Fixed bug
    #70385 (Buffer over-read in exif_read_data with TIFF IFD
    tag byte value of 32 bytes). (Stas) **hash:** * Fixed
    bug #70312 (HAVAL gives wrong hashes in specific cases).
    (letsgolee at naver dot com) **MCrypt:** * Fixed bug
    #69833 (mcrypt fd caching not working). (Anatol)
    **Opcache:** * Fixed bug #70237 (Empty while and
    do-while segmentation fault with opcode on CLI enabled).
    (Dmitry, Laruence) **PCRE:** * Fixed bug #70232
    (Incorrect bump-along behavior with \K and empty string
    match). (cmb) * Fixed bug #70345 (Multiple
    vulnerabilities related to PCRE functions). (Anatol
    Belski) **SOAP:** * Fixed bug #70388 (SOAP
    serialize_function_call() type confusion / RCE). (Stas)
    **SPL:** * Fixed bug #70290 (NULL pointer deref
    (segfault) in spl_autoload via ob_start). (hugh at
    allthethings dot co dot nz) * Fixed bug #70303
    (Incorrect constructor reflection for ArrayObject).
    (cmb) * Fixed bug #70365 (Use-after-free vulnerability
    in unserialize() with SplObjectStorage). (taoguangchen
    at icloud dot com) * Fixed bug #70366 (Use-after-free
    vulnerability in unserialize() with
    SplDoublyLinkedList). (taoguangchen at icloud dot com)
    **Standard:** * Fixed bug #70052 (getimagesize() fails
    for very large and very small WBMP). (cmb) * Fixed bug
    #70157 (parse_ini_string() segmentation fault with
    INI_SCANNER_TYPED). (Tjerk) **XSLT:** * Fixed bug #69782
    (NULL pointer dereference). (Stas)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1260642"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1260647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1260667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1260671"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1260674"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1260683"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1260695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1260707"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1260711"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1260734"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1260741"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1260748"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-September/166632.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bfa72a25"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:23");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^23([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 23.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC23", reference:"php-5.6.13-1.fc23")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php");
}
