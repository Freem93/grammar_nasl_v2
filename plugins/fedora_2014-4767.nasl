#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-4767.
#

include("compat.inc");

if (description)
{
  script_id(73542);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/10/19 22:32:18 $");

  script_cve_id("CVE-2013-7345");
  script_bugtraq_id(66406);
  script_xref(name:"FEDORA", value:"2014-4767");

  script_name(english:"Fedora 20 : php-5.5.11-1.fc20 (2014-4767)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"03 Apr 2014, PHP 5.5.11

Core :

  - Allow zero length comparison in substr_compare() (Tjerk)

    - Fixed bug #60602 (proc_open() changes environment
      array) (Tjerk)

SPL :

  - Added feature #65545 (SplFileObject::fread()) (Tjerk)

cURL :

  - Fixed bug #66109 (Can't reset CURLOPT_CUSTOMREQUEST to
    default behaviour) (Tjerk)

    - Fix compilation on libcurl versions between 7.10.5 and
      7.12.2, inclusive. (Adam)

FPM :

  - Added clear_env configuration directive to disable
    clearenv() call. (Github PR# 598, Paul Annesley)

Fileinfo :

  - Fixed bug #66946 (fileinfo: extensive backtracking in
    awk rule regular expression). (CVE-2013-7345) (Remi)

GD :

  - Fixed bug #66714 (imageconvolution breakage). (Brad
    Daily)

    - Fixed bug #66869 (Invalid 2nd argument crashes
      imageaffinematrixget) (Pierre)

    - Fixed bug #66887 (imagescale - poor quality of scaled
      image). (Remi)

    - Fixed bug #66890 (imagescale segfault). (Remi)

    - Fixed bug #66893 (imagescale ignore method argument).
      (Remi)

Hash :

  - hash_pbkdf2() now works correctly if the $length
    argument is not specified. (Nikita)

Intl :

  - Fixed bug #66873 (A reproductible crash in UConverter
    when given invalid encoding) (Stas)

Mail :

  - Fixed bug #66535 (Don't add newline after
    X-PHP-Originating-Script) (Tjerk)

MySQLi :

  - Fixed bug #66762 (Segfault in mysqli_stmt::bind_result()
    when link closed) (Remi)

OPCache :

  - Added function opcache_is_script_cached(). (Danack)

    - Added information about interned strings usage.
      (Terry, Julien, Dmitry)

Openssl :

  - Fixed bug #66833 (Default disgest algo is still MD5,
    switch to SHA1). (Remi)

GMP :

  - Fixed bug #66872 (invalid argument crashes gmp_testbit)
    (Pierre)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1079846"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-April/131622.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aad326be"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:20");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/16");
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
if (rpm_check(release:"FC20", reference:"php-5.5.11-1.fc20")) flag++;


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
