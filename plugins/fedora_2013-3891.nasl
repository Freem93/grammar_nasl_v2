#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-3891.
#

include("compat.inc");

if (description)
{
  script_id(65773);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/10/19 21:47:15 $");

  script_cve_id("CVE-2013-1635", "CVE-2013-1643");
  script_bugtraq_id(58224, 58766);
  script_xref(name:"FEDORA", value:"2013-3891");

  script_name(english:"Fedora 18 : php-5.4.13-1.fc18 (2013-3891)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Upstream NEWS, 14 Mar 2012, PHP 5.4.13

Core :

  - Fixed bug #64235 (Insteadof not work for class method in
    5.4.11). (Laruence)

    - Implemented FR #64175 (Added HTTP codes as of RFC
      6585). (Jonh Wendell)

    - Fixed bug #64142 (dval to lval different behavior on
      ppc64). (Remi)

    - Fixed bug #64070 (Inheritance with Traits failed with
      error). (Dmitry)

CLI server :

  - Fixed bug #64128 (buit-in web server is broken on
    ppc64). (Remi)

Mbstring :

  - mb_split() can now handle empty matches like
    preg_split() does. (Moriyoshi)

OpenSSL :

  - Fixed bug #61930 (openssl corrupts ssl key resource when
    using openssl_get_publickey()). (Stas)

PDO_mysql :

  - Fixed bug #60840 (undefined symbol:
    mysqlnd_debug_std_no_trace_funcs). (Johannes)

Phar :

  - Fixed timestamp update on Phar contents modification.
    (Dmitry)

SOAP :

  - Added check that soap.wsdl_cache_dir conforms to
    open_basedir (CVE-2013-1635). (Dmitry)

    - Disabled external entities loading (CVE-2013-1643).
      (Dmitry)

SPL :

  - Fixed bug #64264 (SPLFixedArray toArray problem).
    (Laruence)

    - Fixed bug #64228 (RecursiveDirectoryIterator always
      assumes SKIP_DOTS). (patch by kriss at krizalys.com,
      Laruence)

    - Fixed bug #64106 (Segfault on SplFixedArray[][x] = y
      when extended). (Nikita Popov)

    - Fixed bug #52861 (unset fails with ArrayObject and
      deep arrays). (Mike Willbanks)

SNMP :

  - Fixed bug #64124 (IPv6 malformed). (Boris Lytochkin)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=918187"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=918196"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-April/101336.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d4a5454e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:18");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^18([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 18.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC18", reference:"php-5.4.13-1.fc18")) flag++;


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
