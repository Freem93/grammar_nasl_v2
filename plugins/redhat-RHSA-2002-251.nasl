#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2002:251. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12332);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/28 17:44:42 $");

  script_cve_id("CVE-2002-0839", "CVE-2002-0840", "CVE-2002-0843", "CVE-2002-1157");
  script_xref(name:"RHSA", value:"2002:251");

  script_name(english:"RHEL 2.1 : apache (RHSA-2002:251)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated apache and httpd packages are available which fix a number of
security issues for Red Hat Linux Advanced Server 2.1.

[Updated 06 Feb 2003] Added fixed packages for Advanced Workstation
2.1

The Apache HTTP server is a powerful, full-featured, efficient, and
freely-available Web server.

Buffer overflows in the ApacheBench support program (ab.c) in Apache
versions prior to 1.3.27 allow a malicious Web server to cause a
denial of service and possibly execute arbitrary code via a long
response. The Common Vulnerabilities and Exposures project has
assigned the name CVE-2002-0843 to this issue.

Two cross-site scripting vulnerabilities are present in the error
pages for the default '404 Not Found' error, and for the error
response when a plain HTTP request is received on an SSL port. Both of
these issues are only exploitable if the 'UseCanonicalName' setting
has been changed to 'Off', and wildcard DNS is in use. These issues
would allow remote attackers to execute scripts as other Web page
visitors, for instance, to steal cookies. These issues affect versions
of Apache 1.3 before 1.3.26, and versions of mod_ssl before 2.8.12.
The Common Vulnerabilities and Exposures project has assigned the
names CVE-2002-0840 and CVE-2002-1157 to these issues.

The shared memory scoreboard in the HTTP daemon for Apache 1.3, prior
to version 1.3.27, allowed a user running as the 'apache' UID to send
a SIGUSR1 signal to any process as root, resulting in a denial of
service (process kill) or other such behavior that would not normally
be allowed. The Common Vulnerabilities and Exposures project has
assigned the name CVE-2002-0839 to this issue.

All users of the Apache HTTP server are advised to upgrade to the
applicable errata packages. For Red Hat Linux Advanced Server 2.1
these packages include Apache version 1.3.27 which is not vulnerable
to these issues.

Note that the instructions in the 'Solution' section of this errata
contain additional steps required to complete the upgrade process."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2002-0839.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2002-0840.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2002-0843.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2002-1157.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.apacheweek.com/issues/02-10-04"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2002-251.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/06");
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
  rhsa = "RHSA-2002:251";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"apache-1.3.27-2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"apache-devel-1.3.27-2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"apache-manual-1.3.27-2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mod_ssl-2.8.12-2")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache / apache-devel / apache-manual / mod_ssl");
  }
}
