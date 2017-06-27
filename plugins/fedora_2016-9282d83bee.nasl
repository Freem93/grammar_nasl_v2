#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2016-9282d83bee.
#

include("compat.inc");

if (description)
{
  script_id(90465);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/04/13 15:25:34 $");

  script_xref(name:"FEDORA", value:"2016-9282d83bee");

  script_name(english:"Fedora 22 : php-5.6.20-1.fc22 (2016-9282d83bee)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"31 Mar 2016, **PHP 5.6.20** **CLI Server:** * Fixed bug php#69953
(Support MKCALENDAR request method). (Christoph) **Core:** * Fixed bug
php#71596 (Segmentation fault on ZTS with date function (setlocale)).
(Anatol) **Curl:**

  - Fixed bug php#71694 (Support constant
    CURLM_ADDED_ALREADY). (mpyw) **Date:**

    - Fixed bug php#71635 (DatePeriod::getEndDate segfault).
      (Thomas Punt) **Fileinfo:** * Fixed bug php#71527
      (Buffer over-write in finfo_open with malformed magic
      file). (Anatol) **Mbstring:** * Fixed bug php#71906
      (AddressSanitizer: negative-size-param (-1) in
      mbfl_strcut). (Stas) **ODBC:**

  - Fixed bug php#47803, php#69526 (Executing prepared
    statements is succesfull only for the first two
    statements). (einavitamar, Anatol) * Fixed bug php#71860
    (Invalid memory write in phar on filename with \0 in
    name). (Stas) **PDO_DBlib:** * Fixed bug php#54648
    (PDO::MSSQL forces format of datetime fields). (steven,
    Anatol) **Phar:** * Fixed bug php#71625 (Crash in
    php7.dll with bad phar filename). (Anatol) * Fixed bug
    php#71504 (Parsing of tar file with duplicate filenames
    causes memory leak). (Jos Elstgeest) **SNMP:** * Fixed
    bug php#71704 (php_snmp_error() Format String
    Vulnerability). (andrew) **Standard** * Fixed bug
    php#71798 (Integer Overflow in php_raw_url_encode).
    (taoguangchen, Stas)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1323103"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1323106"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1323108"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1323114"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1323118"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-April/181697.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?047f56bc"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/13");
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
if (rpm_check(release:"FC22", reference:"php-5.6.20-1.fc22")) flag++;


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
