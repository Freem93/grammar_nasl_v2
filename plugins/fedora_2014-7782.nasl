#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-7782.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(76392);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/10/19 22:40:33 $");

  script_bugtraq_id(61128, 61776, 61929, 64225, 67118, 67837, 68007, 68120, 68237, 68238, 68239, 68241, 68243);
  script_xref(name:"FEDORA", value:"2014-7782");

  script_name(english:"Fedora 19 : php-5.5.14-1.fc19 (2014-7782)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"26 Jun 2014, PHP 5.5.14

Core :

  - Fixed BC break introduced by patch for bug #67072.
    (Anatol, Stas)

    - Fixed bug #66622 (Closures do not correctly capture
      the late bound class (static::) in some cases). (Levi
      Morrison)

    - Fixed bug #67390 (insecure temporary file use in the
      configure script). (CVE-2014-3981) (Remi)

    - Fixed bug #67399 (putenv with empty variable may lead
      to crash). (Stas)

    - Fixed bug #67498 (phpinfo() Type Confusion Information
      Leak Vulnerability). (Stefan Esser)

CLI server :

  - Fixed Bug #67406 (built-in web-server segfaults on
    startup). (Remi)

Date :

  - Fixed bug #67308 (Serialize of DateTime truncates
    fractions of second). (Adam)

    - Fixed regression in fix for bug #67118 (constructor
      can't be called twice). (Remi)

Fileinfo :

  - Fixed bug #67326 (fileinfo: cdf_read_short_sector
    insufficient boundary check). (CVE-2014-0207)

    - Fixed bug #67410 (fileinfo: mconvert incorrect
      handling of truncated pascal string size).
      (CVE-2014-3478) (Francisco Alonso, Jan Kaluza, Remi)

    - Fixed bug #67411 (fileinfo: cdf_check_stream_offset
      insufficient boundary check). (CVE-2014-3479)
      (Francisco Alonso, Jan Kaluza, Remi)

    - Fixed bug #67412 (fileinfo: cdf_count_chain
      insufficient boundary check). (CVE-2014-3480)
      (Francisco Alonso, Jan Kaluza, Remi)

    - Fixed bug #67413 (fileinfo: cdf_read_property_info
      insufficient boundary check). (CVE-2014-3487)
      (Francisco Alonso, Jan Kaluza, Remi)

Intl :

  - Fixed bug #67349 (Locale::parseLocale Double Free).
    (Stas)

    - Fixed bug #67397 (Buffer overflow in
      locale_get_display_name and uloc_getDisplayName
      (libicu 4.8.1)). (Stas)

Network :

  - Fixed bug #67432 (Fix potential segfault in
    dns_get_record()). (CVE-2014-4049). (Sara)

OPCache :

  - Fixed issue #183 (TMP_VAR is not only used once).
    (Dmitry, Laruence)

OpenSSL :

  - Fixed bug #65698 (certificates validity parsing does not
    work past 2050). (Paul Oehler)

    - Fixed bug #66636 (openssl_x509_parse warning with
      V_ASN1_GENERALIZEDTIME). (Paul Oehler)

PDO-ODBC :

  - Fixed bug #50444 (PDO-ODBC changes for 64-bit).

SOAP :

  - Implemented FR #49898 (Add SoapClient::__getCookies()).
    (Boro Sitnikovski)

SPL :

  - Fixed bug #66127 (Segmentation fault with ArrayObject
    unset). (Stas)

    - Fixed bug #67359 (Segfault in
      recursiveDirectoryIterator). (Laruence)

    - Fixed bug #67360 (Missing element after
      ArrayObject::getIterator). (Adam)

    - Fixed bug #67492 (unserialize() SPL ArrayObject /
      SPLObjectStorage Type Confusion). (CVE-2014-3515)
      (Stefan Esser)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-July/135138.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ecbdbc13"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:19");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/08");
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
if (! ereg(pattern:"^19([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 19.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC19", reference:"php-5.5.14-1.fc19")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php");
}
