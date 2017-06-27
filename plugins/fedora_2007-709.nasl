#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-709.
#

include("compat.inc");

if (description)
{
  script_id(26115);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/08 20:11:35 $");

  script_cve_id("CVE-2007-2756", "CVE-2007-2872", "CVE-2007-3799", "CVE-2007-3996", "CVE-2007-3998", "CVE-2007-4658", "CVE-2007-4670");
  script_xref(name:"FEDORA", value:"2007-709");

  script_name(english:"Fedora Core 6 : php-5.1.6-3.7.fc6 (2007-709)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes a number of security issues in PHP :

  - various integer overflow flaws were found in the PHP gd
    extension. A script that could be forced to resize
    images from an untrusted source could possibly allow a
    remote attacker to execute arbitrary code as the apache
    user. (CVE-2007-3996)

  - an integer overflow flaw was found in the PHP
    chunk_split function. If a remote attacker was able to
    pass arbitrary data to the third argument of chunk_split
    they could possibly execute arbitrary code as the apache
    user. Note that it is unusual for a PHP script to use
    the chunk_script function with a user-supplied third
    argument. (CVE-2007-2872)

  - a previous security update introduced a bug into PHP
    session cookie handling. This could allow an attacker to
    stop a victim from viewing a vulnerable website if the
    victim has first visited a malicious web page under the
    control of the attacker, and that page can set a cookie
    for the vulnerable website. (CVE-2007-4670)

  - a flaw was found in the PHP money_format function. If a
    remote attacker was able to pass arbitrary data to the
    money_format function this could possibly result in an
    information leak or denial of service. Note that is is
    unusual for a PHP script to pass user-supplied data to
    the money_format function. (CVE-2007-4658)

  - a flaw was found in the PHP wordwrap function. If a
    remote attacker was able to pass arbitrary data to the
    wordwrap function this could possibly result in a denial
    of service. (CVE-2007-3998)

  - a bug was found in PHP session cookie handling. This
    could allow an attacker to create a cross-site cookie
    insertion attack if a victim follows an untrusted
    carefully-crafted URL. (CVE-2007-3799)

  - an infinite-loop flaw was discovered in the PHP gd
    extension. A script that could be forced to process PNG
    images from an untrusted source could allow a remote
    attacker to cause a denial of service. (CVE-2007-2756)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-September/003879.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?52cd3b80"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(20, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-ncurses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 6.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC6", reference:"php-5.1.6-3.7.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"php-bcmath-5.1.6-3.7.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"php-cli-5.1.6-3.7.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"php-common-5.1.6-3.7.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"php-dba-5.1.6-3.7.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"php-debuginfo-5.1.6-3.7.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"php-devel-5.1.6-3.7.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"php-gd-5.1.6-3.7.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"php-imap-5.1.6-3.7.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"php-ldap-5.1.6-3.7.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"php-mbstring-5.1.6-3.7.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"php-mysql-5.1.6-3.7.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"php-ncurses-5.1.6-3.7.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"php-odbc-5.1.6-3.7.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"php-pdo-5.1.6-3.7.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"php-pgsql-5.1.6-3.7.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"php-snmp-5.1.6-3.7.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"php-soap-5.1.6-3.7.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"php-xml-5.1.6-3.7.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"php-xmlrpc-5.1.6-3.7.fc6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php / php-bcmath / php-cli / php-common / php-dba / php-debuginfo / etc");
}
