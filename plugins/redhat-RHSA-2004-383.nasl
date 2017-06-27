#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2004:383. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14212);
  script_version ("$Revision: 1.27 $");
  script_cvs_date("$Date: 2016/12/28 17:44:44 $");

  script_cve_id("CVE-2002-0029");
  script_osvdb_id(8330);
  script_xref(name:"CERT", value:"844360");
  script_xref(name:"RHSA", value:"2004:383");

  script_name(english:"RHEL 2.1 : glibc (RHSA-2004:383)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated glibc packages that fix a security flaw in the resolver as
well as dlclose handling are now available.

The GNU libc packages (known as glibc) contain the standard C
libraries used by applications.

A security audit of the glibc packages in Red Hat Enterprise Linux 2.1
found a flaw in the resolver library which was originally reported as
affecting versions of ISC BIND 4.9. This flaw also applied to glibc
versions before 2.3.2. An attacker who is able to send DNS responses
(perhaps by creating a malicious DNS server) could remotely exploit
this vulnerability to execute arbitrary code or cause a denial of
service. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2002-0029 to this issue.

These updated packages also fix a dlclose function bug on certain
shared libraries, which caused program crashes.

All users of glibc should upgrade to these updated packages, which
resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2002-0029.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2004-383.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/11/12");
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

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2004:383";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"glibc-2.2.4-32.17")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i686", reference:"glibc-2.2.4-32.17")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"glibc-common-2.2.4-32.17")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"glibc-devel-2.2.4-32.17")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"glibc-profile-2.2.4-32.17")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"nscd-2.2.4-32.17")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-common / glibc-devel / glibc-profile / nscd");
  }
}
