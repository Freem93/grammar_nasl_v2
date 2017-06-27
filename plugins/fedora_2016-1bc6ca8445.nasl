#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2016-1bc6ca8445.
#

include("compat.inc");

if (description)
{
  script_id(89487);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/03/04 16:10:31 $");

  script_xref(name:"FEDORA", value:"2016-1bc6ca8445");

  script_name(english:"Fedora 22 : php-5.6.18-1.fc22 (2016-1bc6ca8445)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"04 Feb 2016, **PHP 5.6.18** **Core:** * Fixed bug php#71039 (exec
functions ignore length but look for NULL termination). (Anatol) *
Fixed bug php#71089 (No check to duplicate zend_extension). (Remi) *
Fixed bug php#71201 (round() segfault on 64-bit builds). (Anatol) *
Added support for new HTTP 451 code. (Julien) * Fixed bug php#71273 (A
wrong ext directory setup in php.ini leads to crash). (Anatol) * Fixed
bug php#71323 (Output of stream_get_meta_data can be falsified by its
input). (Leo Gaspard) * Fixed bug php#71459 (Integer overflow in
iptcembed()). (Stas) **Apache2handler:** * Fix >2G Content-Length
headers in apache2handler. (Adam Harvey) **FTP:** * Implemented FR
php#55651 (Option to ignore the returned FTP PASV address). (abrender
at elitehosts dot com) **Opcache:** * Fixed bug php#71127 (Define in
auto_prepend_file is overwrite). (Laruence) * Fixed bug php#71024
(Unable to use PHP 7.0 x64 side-by-side with PHP 5.6 x32 on the same
server). (Anatol) **Phar:** * Fixed bug php#71354 (Heap corruption in
tar/zip/phar parser). (Stas) * Fixed bug php#71391 (NULL pointer
Dereference in phar_tar_setupmetadata()). (Stas) * Fixed bug php#71488
(Stack overflow when decompressing tar archives). (Stas) **Session:**
* Fixed bug php#69111 (Crash in SessionHandler::read()). (Anatol)
**SOAP:** * Fixed bug php#70979 (crash with bad soap request).
(Anatol) **SPL:** * Fixed bug php#71204 (segfault if clean
spl_autoload_funcs while autoloading). (Laruence) **WDDX:** * Fixed
bug php#71335 (Type Confusion in WDDX Packet Deserialization). (Stas)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-February/177278.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ea38452e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/04");
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
if (! ereg(pattern:"^22([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 22.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC22", reference:"php-5.6.18-1.fc22")) flag++;


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
