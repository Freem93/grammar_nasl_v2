#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1244. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77697);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/06 15:50:59 $");

  script_cve_id("CVE-2014-0591");
  script_bugtraq_id(64801);
  script_osvdb_id(101973);
  script_xref(name:"RHSA", value:"2014:1244");

  script_name(english:"RHEL 5 : bind97 (RHSA-2014:1244)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated bind97 packages that fix one security issue and one bug are
now available for Red Hat Enterprise Linux 5.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The Berkeley Internet Name Domain (BIND) is an implementation of the
Domain Name System (DNS) protocols. It contains a DNS server (named),
a resolver library with routines for applications to use when
interfacing with DNS, and tools for verifying that the DNS server is
operating correctly. These packages contain version 9.7 of the BIND
suite.

A denial of service flaw was found in the way BIND handled queries for
NSEC3-signed zones. A remote attacker could use this flaw against an
authoritative name server that served NCES3-signed zones by sending a
specially crafted query, which, when processed, would cause named to
crash. (CVE-2014-0591)

Note: The CVE-2014-0591 issue does not directly affect the version of
bind97 shipped in Red Hat Enterprise Linux 5. This issue is being
addressed however to assure it is not introduced in future builds of
bind97 (possibly built with a different compiler or C library
optimization).

This update also fixes the following bug :

* Previously, the bind97 initscript did not check for the existence of
the ROOTDIR variable when shutting down the named daemon. As a
consequence, some parts of the file system that are mounted when using
bind97 in a chroot environment were unmounted on daemon shut down,
even if bind97 was not running in a chroot environment. With this
update, the initscript has been fixed to check for the existence of
the ROOTDIR variable when unmounting some parts of the file system on
named daemon shut down. Now, when shutting down bind97 that is not
running in a chroot environment, no parts of the file system are
unmounted. (BZ#1059118)

All bind97 users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing the update, the BIND daemon (named) will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0591.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-1244.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind97");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind97-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind97-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind97-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind97-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind97-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2014:1244";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"bind97-9.7.0-21.P2.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"bind97-9.7.0-21.P2.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"bind97-9.7.0-21.P2.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"bind97-chroot-9.7.0-21.P2.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"bind97-chroot-9.7.0-21.P2.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"bind97-chroot-9.7.0-21.P2.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"bind97-debuginfo-9.7.0-21.P2.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"bind97-devel-9.7.0-21.P2.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"bind97-libs-9.7.0-21.P2.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"bind97-utils-9.7.0-21.P2.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"bind97-utils-9.7.0-21.P2.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"bind97-utils-9.7.0-21.P2.el5")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind97 / bind97-chroot / bind97-debuginfo / bind97-devel / etc");
  }
}
