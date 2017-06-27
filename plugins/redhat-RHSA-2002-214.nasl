#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2002:214. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12326);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/28 17:44:42 $");

  script_cve_id("CVE-2002-0985", "CVE-2002-0986");
  script_osvdb_id(2111, 2160);
  script_xref(name:"RHSA", value:"2002:214");

  script_name(english:"RHEL 2.1 : php (RHSA-2002:214)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"PHP versions up to and including 4.2.2 contain vulnerabilities in the
mail() function, allowing local script authors to bypass safe mode
restrictions and possibly allowing remote attackers to insert
arbitrary mail headers or content.

[Updated 13 Jan 2003] Added fixed packages for the Itanium (IA64)
architecture.

[Updated 06 Feb 2003] Added fixed packages for Advanced Workstation
2.1

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP server.

The mail function in PHP 4.x to 4.2.2 may allow local script authors
to bypass safe mode restrictions and modify command line arguments to
the MTA (such as sendmail) in the 5th argument to mail(), altering MTA
behavior and possibly executing arbitrary local commands.

The mail function in PHP 4.x to 4.2.2 does not filter ASCII control
characters from its arguments, which could allow remote attackers to
modify mail message content, including mail headers, and possibly use
PHP as a 'spam proxy.'

Script authors should note that all input data should be checked for
unsafe data by any PHP scripts which call functions such as mail().

Note that this PHP errata, as did RHSA-2002:129, enforces memory
limits on the size of the PHP process to prevent a badly generated
script from becoming a possible source for a denial of service attack.
The default process size is 8Mb, though you can adjust this as you
deem necessary through the php.ini directive memory_limit. For
example, to change the process memory limit to 4MB, add the 
following :

memory_limit 4194304

Important Note: There are special instructions you should follow
regarding your /etc/php.ini configuration file in the 'Solution'
section below."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2002-0985.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2002-0986.html"
  );
  # http://marc.theaimsgroup.com/?l=bugtraq&m=103011916928204
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=bugtraq&m=103011916928204"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2002-214.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/06");
  script_set_attribute(attribute:"vuln_publication_date", value:"2003/07/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^2\.1([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);
if (cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i386", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2002:214";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"php-4.1.2-2.1.6")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"php-devel-4.1.2-2.1.6")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"php-imap-4.1.2-2.1.6")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"php-ldap-4.1.2-2.1.6")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"php-manual-4.1.2-2.1.6")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"php-mysql-4.1.2-2.1.6")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"php-odbc-4.1.2-2.1.6")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"php-pgsql-4.1.2-2.1.6")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php / php-devel / php-imap / php-ldap / php-manual / php-mysql / etc");
  }
}
