#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-13013.
#

include("compat.inc");

if (description)
{
  script_id(78661);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/10/19 22:14:41 $");

  script_bugtraq_id(64225, 67118, 70611, 70665, 70666);
  script_xref(name:"FEDORA", value:"2014-13013");

  script_name(english:"Fedora 20 : php-5.5.18-1.fc20 (2014-13013)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"16 Oct 2014, PHP 5.5.18

Core :

  - Fixed bug #67985 (Incorrect last used array index copied
    to new array after unset). (Tjerk)

    - Fixed bug #67739 (Windows 8.1/Server 2012 R2 OS build
      number reported as 6.2 (instead of 6.3)). (Christian
      Wenz)

    - Fixed bug #67633 (A foreach on an array returned from
      a function not doing copy-on-write). (Nikita)

    - Fixed bug #51800 (proc_open on Windows hangs forever).
      (Anatol)

    - Fixed bug #68044 (Integer overflow in unserialize()
      (32-bits only)). (CVE-2014-3669) (Stas)

cURL :

  - Fixed bug #68089 (NULL byte injection - cURL lib).
    (Stas)

EXIF :

  - Fixed bug #68113 (Heap corruption in exif_thumbnail()).
    (CVE-2014-3670) (Stas)

FPM :

  - Fixed bug #65641 (PHP-FPM incorrectly defines the
    SCRIPT_NAME variable when using Apache, mod_proxy-fcgi
    and ProxyPass). (Remi)

OpenSSL :

  - Revert regression introduced by fix of bug #41631

Reflection :

  - Fixed bug #68103 (Duplicate entry in Reflection for
    class alias). (Remi)

Session :

  - Fixed bug #67972 (SessionHandler Invalid memory read
    create_sid()). (Adam)

XMLRPC :

  - Fixed bug #68027 (Global buffer overflow in mkgmtime()
    function). (CVE-2014-3668) (Stas)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-October/141349.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?023c6872"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:20");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^20([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 20.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC20", reference:"php-5.5.18-1.fc20")) flag++;


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
