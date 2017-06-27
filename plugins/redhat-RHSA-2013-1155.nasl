#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1155. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78968);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/01/05 16:29:43 $");

  script_cve_id("CVE-2013-4236");
  script_xref(name:"RHSA", value:"2013:1155");

  script_name(english:"RHEL 6 : rhev 3.2.2 - vdsm (RHSA-2013:1155)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated vdsm packages that fix one security issue and various bugs are
now available.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

[Updated 21 August 2013] The packages list in this erratum has been
updated to include missing packages for the 'Red Hat Enterprise Virt
Management Agent (v 6 x86_64)' channel (also known as
'rhel-x86_64-rhev-mgmt-agent-6'). No changes have been made to the
original packages.

VDSM is a management module that serves as a Red Hat Enterprise
Virtualization Manager agent on Red Hat Enterprise Virtualization
Hypervisor or Red Hat Enterprise Linux hosts.

It was found that the fix for CVE-2013-0167 released via
RHSA-2013:0886 was incomplete. A privileged guest user could
potentially use this flaw to make the host the guest is running on
unavailable to the management server. (CVE-2013-4236)

This issue was found by David Gibson of Red Hat.

This update also fixes the following bugs :

* Previously, failure to move a disk produced a 'truesize' exit
message, which was not informative. Now, failure to move a disk
produces a more helpful error message explaining that the volume is
corrupted or missing. (BZ#985556)

* The LVM filter has been updated to only access physical volumes by
full /dev/mapper paths in order to improve performance. This replaces
the previous behavior of scanning all devices including logical
volumes on physical volumes. (BZ#983599)

* The log collector now collects /var/log/sanlock.log from
Hypervisors, to assist in debugging sanlock errors. (BZ#987042)

* When the poollist parameter was not defined, dumpStorageTable
crashed, causing SOS report generation to fail with the error
'IndexError: list index out of range'. VDSM now handles this
exception, so the log collector can generate host SOS reports.
(BZ#985069)

* Previously, VDSM used the memAvailable parameter to report available
memory on a host, which could return negative values if memory
overcommitment was in use. Now, the new memFree parameter returns the
actual amount of free memory on a host. (BZ#982639)

All users managing Red Hat Enterprise Linux Virtualization hosts using
Red Hat Enterprise Virtualization Manager are advised to install these
updated packages, which fix these issues.

These updated packages will be provided to users of Red Hat Enterprise
Virtualization Hypervisor in the next rhev-hypervisor6 errata package."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4236.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://rhn.redhat.com/errata/RHSA-2013-0886.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1155.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-bootstrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-hook-vhostmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-reg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/08");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:1155";
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
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"vdsm-4.10.2-24.0.el6ev")) flag++;
  if (rpm_check(release:"RHEL6", reference:"vdsm-bootstrap-4.10.2-24.0.el6ev")) flag++;
  if (rpm_check(release:"RHEL6", reference:"vdsm-cli-4.10.2-24.0.el6ev")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"vdsm-debuginfo-4.10.2-24.0.el6ev")) flag++;
  if (rpm_check(release:"RHEL6", reference:"vdsm-hook-vhostmd-4.10.2-24.0.el6ev")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"vdsm-python-4.10.2-24.0.el6ev")) flag++;
  if (rpm_check(release:"RHEL6", reference:"vdsm-reg-4.10.2-24.0.el6ev")) flag++;
  if (rpm_check(release:"RHEL6", reference:"vdsm-xmlrpc-4.10.2-24.0.el6ev")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "vdsm / vdsm-bootstrap / vdsm-cli / vdsm-debuginfo / etc");
  }
}
