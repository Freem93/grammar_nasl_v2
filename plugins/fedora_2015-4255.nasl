#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-4255.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(82284);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/10/19 23:06:18 $");

  script_bugtraq_id(72539);
  script_xref(name:"FEDORA", value:"2015-4255");

  script_name(english:"Fedora 22 : php-5.6.7-2.fc22 (2015-4255)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**19 Mar 2015, PHP 5.6.7**

Core :

  - Fixed bug #69174 (leaks when unused inner class use
    traits precedence). (Laruence)

    - Fixed bug #69139 (Crash in gc_zval_possible_root on
      unserialize). (Laruence)

    - Fixed bug #69121 (Segfault in get_current_user when
      script owner is not in passwd with ZTS build). (dan at
      syneto dot net)

    - Fixed bug #65593 (Segfault when calling ob_start from
      output buffering callback). (Mike)

    - Fixed bug #68986 (pointer returned by
      php_stream_fopen_temporary_file not validated in
      memory.c). (nayana at ddproperty dot com)

    - Fixed bug #68166 (Exception with invalid character
      causes segv). (Rasmus)

    - Fixed bug #69141 (Missing arguments in reflection info
      for some builtin functions). (kostyantyn dot lysyy at
      oracle dot com)

    - Fixed bug #68976 (Use After Free Vulnerability in
      unserialize()) (CVE-2015-0231). (Stas)

    - Fixed bug #69134 (Per Directory Values overrides
      PHP_INI_SYSTEM configuration options). (Anatol Belski)

    - Fixed bug #69207 (move_uploaded_file allows nulls in
      path). (Stas)

CGI :

  - Fixed bug #69015 (php-cgi's getopt does not see $argv).
    (Laruence)

CLI :

  - Fixed bug #67741 (auto_prepend_file messes up __LINE__).
    (Reeze Xia)

cURL :

  - Fixed bug #69088 (PHP_MINIT_FUNCTION does not fully
    initialize cURL on Win32). (Grant Pannell)

    - Add CURLPROXY_SOCKS4A and CURLPROXY_SOCKS5_HOSTNAME
      constants if supported by libcurl. (Linus Unneback)

Ereg :

  - Fixed bug #69248 (heap overflow vulnerability in
    regcomp.c) (CVE-2015-2305). (Stas)

FPM :

  - Fixed bug #68822 (request time is reset too early).
    (honghu069 at 163 dot com)

ODBC :

  - Fixed bug #68964 (Allowed memory size exhausted with
    odbc_exec). (Anatol)

Opcache :

  - Fixed bug #69159 (Opcache causes problem when passing a
    variable variable to a function). (Dmitry, Laruence)

    - Fixed bug #69125 (Array numeric string as key).
      (Laruence)

    - Fixed bug #69038 (switch(SOMECONSTANT) misbehaves).
      (Laruence)

OpenSSL :

  - Fixed bug #68912 (Segmentation fault at
    openssl_spki_new). (Laruence)

    - Fixed bug #61285, #68329, #68046, #41631 (encrypted
      streams don't observe socket timeouts). (Brad
      Broerman)

    - Fixed bug #68920 (use strict peer_fingerprint input
      checks) (Daniel Lowrey)

    - Fixed bug #68879 (IP Address fields in subjectAltNames
      not used) (Daniel Lowrey)

    - Fixed bug #68265 (SAN match fails with trailing DNS
      dot) (Daniel Lowrey)

    - Fixed bug #67403 (Add signatureType to
      openssl_x509_parse) (Daniel Lowrey)

    - Fixed bug (#69195 Inconsistent stream crypto values
      across versions) (Daniel Lowrey)

pgsql :

  - Fixed bug #68638 (pg_update() fails to store infinite
    values). (william dot welter at 4linux dot com dot br,
    Laruence)

Readline :

  - Fixed bug #69054 (Null dereference in
    readline_(read|write)_history() without parameters).
    (Laruence)

SOAP :

  - Fixed bug #69085 (SoapClient's __call() type confusion
    through unserialize()). (andrea dot palazzo at truel dot
    it, Laruence)

SPL :

  - Fixed bug #69108 ('Segmentation fault' when
    (de)serializing SplObjectStorage). (Laruence)

    - Fixed bug #68557 (RecursiveDirectoryIterator::seek(0)
      broken after calling getChildren()). (Julien)

ZIP :

  - Fixed bug #69253 (ZIP Integer Overflow leads to writing
    past heap boundary) (CVE-2015-2331). (Stas)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1204868"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-March/153269.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?215d7f24"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC22", reference:"php-5.6.7-2.fc22")) flag++;


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
