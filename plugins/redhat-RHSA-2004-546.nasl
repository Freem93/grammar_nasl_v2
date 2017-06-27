#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2004:546. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15441);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/12/28 17:55:16 $");

  script_cve_id("CVE-2004-0884");
  script_osvdb_id(10554, 10555);
  script_xref(name:"RHSA", value:"2004:546");

  script_name(english:"RHEL 2.1 / 3 : cyrus-sasl (RHSA-2004:546)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated cyrus-sasl packages that fix a setuid and setgid application
vulnerability are now available.

[Updated 7th October 2004] Revised cryus-sasl packages have been added
for Red Hat Enterprise Linux 3; the patch in the previous packages
broke interaction with ldap.

The cyrus-sasl package contains the Cyrus implementation of SASL. SASL
is the Simple Authentication and Security Layer, a method for adding
authentication support to connection-based protocols.

At application startup, libsasl and libsasl2 attempts to build a list
of all available SASL plug-ins which are available on the system. To
do so, the libraries search for and attempt to load every shared
library found within the plug-in directory. This location can be set
with the SASL_PATH environment variable.

In situations where an untrusted local user can affect the environment
of a privileged process, this behavior could be exploited to run
arbitrary code with the privileges of a setuid or setgid application.
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2004-0884 to this issue.

Users of cyrus-sasl should upgrade to these updated packages, which
contain backported patches and are not vulnerable to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0884.html"
  );
  # https://bugzilla.andrew.cmu.edu/cgi-bin/cvsweb.cgi/src/sasl/lib/common.c.diff?
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4389037d"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2004-546.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cyrus-sasl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cyrus-sasl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cyrus-sasl-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cyrus-sasl-md5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cyrus-sasl-plain");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/08");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/08");
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
if (! ereg(pattern:"^(2\.1|3)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1 / 3.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2004:546";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"cyrus-sasl-1.5.24-26")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"cyrus-sasl-devel-1.5.24-26")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"cyrus-sasl-gssapi-1.5.24-26")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"cyrus-sasl-md5-1.5.24-26")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"cyrus-sasl-plain-1.5.24-26")) flag++;

  if (rpm_check(release:"RHEL3", reference:"cyrus-sasl-2.1.15-10")) flag++;
  if (rpm_check(release:"RHEL3", reference:"cyrus-sasl-devel-2.1.15-10")) flag++;
  if (rpm_check(release:"RHEL3", reference:"cyrus-sasl-gssapi-2.1.15-10")) flag++;
  if (rpm_check(release:"RHEL3", reference:"cyrus-sasl-md5-2.1.15-10")) flag++;
  if (rpm_check(release:"RHEL3", reference:"cyrus-sasl-plain-2.1.15-10")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cyrus-sasl / cyrus-sasl-devel / cyrus-sasl-gssapi / cyrus-sasl-md5 / etc");
  }
}
