#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2016-e205218629.
#

include("compat.inc");

if (description)
{
  script_id(92187);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/10/18 17:03:07 $");

  script_cve_id("CVE-2016-4537", "CVE-2016-4539", "CVE-2016-4540", "CVE-2016-4542");
  script_xref(name:"FEDORA", value:"2016-e205218629");

  script_name(english:"Fedora 22 : php (2016-e205218629)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"28 Apr 2016, **PHP 5.6.21**

** Core: **

  - Fixed bug #69537 (__debugInfo with empty string for key
    gives error). (krakjoe)

  - Fixed bug #71841 (EG(error_zval) is not handled well).
    (Laruence)

**BCmath:**

  - Fixed bug #72093 (bcpowmod accepts negative scale and
    corrupts _one_ definition). (Stas)

**Curl:**

  - Fixed bug #71831 (CURLOPT_NOPROXY applied as long
    instead of string). (Michael Sierks) 

**Date:**

  - Fixed bug #71889 (DateInterval::format Segmentation
    fault). (Thomas Punt)

**EXIF:**

  - Fixed bug #72094 (Out of bounds heap read access in exif
    header processing). (Stas)

**GD:**

  - Fixed bug #71952 (Corruption inside
    imageaffinematrixget). (Stas)

  - Fixed bug #71912 (libgd: signedness vulnerability).
    (Stas)

**Intl:**

  - Fixed bug #72061 (Out-of-bounds reads in
    zif_grapheme_stripos with negative offset). (Stas)

**OCI8:**

  - Fixed bug #71422 (Fix ORA-01438: value larger than
    specified precision allowed for this column). (Chris
    Jones)

**ODBC:**

  - Fixed bug #63171 (Script hangs after
    max_execution_time). (Remi)

**Opcache:**

  - Fixed bug #71843 (null ptr deref
    ZEND_RETURN_SPEC_CONST_HANDLER). (Laruence)

**PDO:**

  - Fixed bug #52098 (Own PDOStatement implementation ignore
    __call()). (Daniel Kalaspuffar, Julien)

  - Fixed bug #71447 (Quotes inside comments not properly
    handled). (Matteo)

**Postgres:**

  - Fixed bug #71820 (pg_fetch_object binds parameters
    before call constructor). (Anatol)

**SPL:**

  - Fixed bug #67582 (Cloned SplObjectStorage with
    overwritten getHash fails offsetExists()). (Nikita)

**Standard:**

  - Fixed bug #71840 (Unserialize accepts wrongly data).
    (Ryat, Laruence)

  - Fixed bug #67512 (php_crypt() crashes if crypt_r() does
    not exist or _REENTRANT is not defined). (Nikita)

**XML:**

  - Fixed bug #72099 (xml_parse_into_struct segmentation
    fault). (Stas)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2016-e205218629"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/14");
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
if (! ereg(pattern:"^22([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 22", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC22", reference:"php-5.6.21-1.fc22")) flag++;


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
