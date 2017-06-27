#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0126. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57929);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/01/05 16:04:21 $");

  script_cve_id("CVE-2009-5029", "CVE-2009-5064", "CVE-2010-0830", "CVE-2011-1089", "CVE-2011-4609");
  script_bugtraq_id(40063, 46740, 50898, 51439);
  script_osvdb_id(65077, 74278, 74883, 77508, 78316);
  script_xref(name:"RHSA", value:"2012:0126");

  script_name(english:"RHEL 5 : glibc (RHSA-2012:0126)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated glibc packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The glibc packages contain the standard C libraries used by multiple
programs on the system. These packages contain the standard C and the
standard math libraries. Without these two libraries, a Linux system
cannot function properly.

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the way the glibc library read timezone files. If a
carefully-crafted timezone file was loaded by an application linked
against glibc, it could cause the application to crash or,
potentially, execute arbitrary code with the privileges of the user
running the application. (CVE-2009-5029)

A flaw was found in the way the ldd utility identified dynamically
linked libraries. If an attacker could trick a user into running ldd
on a malicious binary, it could result in arbitrary code execution
with the privileges of the user running ldd. (CVE-2009-5064)

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the way the glibc library loaded ELF (Executable and Linking
Format) files. If a carefully-crafted ELF file was loaded by an
application linked against glibc, it could cause the application to
crash or, potentially, execute arbitrary code with the privileges of
the user running the application. (CVE-2010-0830)

It was found that the glibc addmntent() function, used by various
mount helper utilities, did not handle certain errors correctly when
updating the mtab (mounted file systems table) file. If such utilities
had the setuid bit set, a local attacker could use this flaw to
corrupt the mtab file. (CVE-2011-1089)

A denial of service flaw was found in the remote procedure call (RPC)
implementation in glibc. A remote attacker able to open a large number
of connections to an RPC service that is using the RPC implementation
from glibc, could use this flaw to make that service use an excessive
amount of CPU time. (CVE-2011-4609)

Red Hat would like to thank the Ubuntu Security Team for reporting
CVE-2010-0830, and Dan Rosenberg for reporting CVE-2011-1089. The
Ubuntu Security Team acknowledges Dan Rosenberg as the original
reporter of CVE-2010-0830.

Users should upgrade to these updated packages, which resolve these
issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-5029.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-5064.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-0830.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1089.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-4609.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-0126.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:0126";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL5", reference:"glibc-2.5-65.el5_7.3")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"glibc-common-2.5-65.el5_7.3")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"glibc-common-2.5-65.el5_7.3")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"glibc-common-2.5-65.el5_7.3")) flag++;
  if (rpm_check(release:"RHEL5", reference:"glibc-devel-2.5-65.el5_7.3")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"glibc-headers-2.5-65.el5_7.3")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"glibc-headers-2.5-65.el5_7.3")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"glibc-headers-2.5-65.el5_7.3")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"glibc-utils-2.5-65.el5_7.3")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"glibc-utils-2.5-65.el5_7.3")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"glibc-utils-2.5-65.el5_7.3")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"nscd-2.5-65.el5_7.3")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"nscd-2.5-65.el5_7.3")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"nscd-2.5-65.el5_7.3")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-common / glibc-devel / glibc-headers / glibc-utils / etc");
  }
}
