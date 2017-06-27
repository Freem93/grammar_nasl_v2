#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0120. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63403);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/01/05 16:17:30 $");

  script_cve_id("CVE-2012-3417");
  script_bugtraq_id(55066);
  script_osvdb_id(84729);
  script_xref(name:"RHSA", value:"2013:0120");

  script_name(english:"RHEL 5 : quota (RHSA-2013:0120)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated quota package that fixes one security issue and multiple
bugs is now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The quota package provides system administration tools for monitoring
and limiting user and group disk usage on file systems.

It was discovered that the rpc.rquotad service did not use
tcp_wrappers correctly. Certain hosts access rules defined in
'/etc/hosts.allow' and '/etc/hosts.deny' may not have been honored,
possibly allowing remote attackers to bypass intended access
restrictions. (CVE-2012-3417)

This issue was discovered by the Red Hat Security Response Team.

This update also fixes the following bugs :

* Prior to this update, values were not properly transported via the
remote procedure call (RPC) and interpreted by the client when
querying the quota usage or limits for network-mounted file systems if
the quota values were 2^32 kilobytes or greater. As a consequence, the
client reported mangled values. This update modifies the underlying
code so that such values are correctly interpreted by the client.
(BZ#667360)

* Prior to this update, warnquota sent messages about exceeded quota
limits from a valid domain name if the warnquota tool was enabled to
send warning e-mails and the superuser did not change the default
warnquota configuration. As a consequence, the recipient could reply
to invalid addresses. This update modifies the default warnquota
configuration to use the reserved example.com. domain. Now, warnings
about exceeded quota limits are sent from the reserved domain that
inform the superuser to change to the correct value. (BZ#680429)

* Previously, quota utilities could not recognize the file system as
having quotas enabled and refused to operate on it due to incorrect
updating of /etc/mtab. This update prefers /proc/mounts to get a list
of file systems with enabled quotas. Now, quota utilities recognize
file systems with enabled quotas as expected. (BZ#689822)

* Prior to this update, the setquota(8) tool on XFS file systems
failed to set disk limits to values greater than 2^31 kilobytes. This
update modifies the integer conversion in the setquota(8) tool to use
a 64-bit variable big enough to store such values. (BZ#831520)

All users of quota are advised to upgrade to this updated package,
which contains backported patches to resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3417.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0120.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected quota and / or quota-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:quota");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:quota-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2013:0120";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"quota-3.13-8.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"quota-3.13-8.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"quota-3.13-8.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"quota-debuginfo-3.13-8.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"quota-debuginfo-3.13-8.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"quota-debuginfo-3.13-8.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "quota / quota-debuginfo");
  }
}
