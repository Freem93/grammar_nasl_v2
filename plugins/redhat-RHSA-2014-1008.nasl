#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1008. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77012);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/06 15:40:58 $");

  script_cve_id("CVE-2014-3560");
  script_bugtraq_id(69021);
  script_xref(name:"RHSA", value:"2014:1008");

  script_name(english:"RHEL 7 : samba (RHSA-2014:1008)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated samba packages that fix one security issue and one bug are now
available for Red Hat Enterprise Linux 7.

The Red Hat Security Response Team has rated this update as having
Important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

Samba is an open source implementation of the Server Message Block
(SMB) or Common Internet File System (CIFS) protocol, which allows
PC-compatible machines to share files, printers, and other
information.

A heap-based buffer overflow flaw was found in Samba's NetBIOS message
block daemon (nmbd). An attacker on the local network could use this
flaw to send specially crafted packets that, when processed by nmbd,
could possibly lead to arbitrary code execution with root privileges.
(CVE-2014-3560)

This update also fixes the following bug :

* Prior to this update, Samba incorrectly used the O_TRUNC flag when
using the open(2) system call to access the contents of a file that
was already opened by a different process, causing the file's previous
contents to be removed. With this update, the O_TRUNC flag is no
longer used in the above scenario, and file corruption no longer
occurs. (BZ#1115490)

All Samba users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing this update, the smb service will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3560.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.samba.org/samba/security/CVE-2014-3560"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-1008.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-dc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-test-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-vfs-glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-modules");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/06");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:1008";
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
  if (rpm_check(release:"RHEL7", reference:"libsmbclient-4.1.1-37.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libsmbclient-devel-4.1.1-37.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libwbclient-4.1.1-37.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libwbclient-devel-4.1.1-37.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"samba-4.1.1-37.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-4.1.1-37.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"samba-client-4.1.1-37.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-client-4.1.1-37.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"samba-common-4.1.1-37.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-common-4.1.1-37.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"samba-dc-4.1.1-37.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-dc-4.1.1-37.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"samba-dc-libs-4.1.1-37.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-dc-libs-4.1.1-37.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", reference:"samba-debuginfo-4.1.1-37.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", reference:"samba-devel-4.1.1-37.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", reference:"samba-libs-4.1.1-37.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"samba-pidl-4.1.1-37.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-pidl-4.1.1-37.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"samba-python-4.1.1-37.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-python-4.1.1-37.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"samba-test-4.1.1-37.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-test-4.1.1-37.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"samba-test-devel-4.1.1-37.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-test-devel-4.1.1-37.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-vfs-glusterfs-4.1.1-37.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"samba-winbind-4.1.1-37.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-winbind-4.1.1-37.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"samba-winbind-clients-4.1.1-37.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-winbind-clients-4.1.1-37.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"samba-winbind-krb5-locator-4.1.1-37.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-winbind-krb5-locator-4.1.1-37.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", reference:"samba-winbind-modules-4.1.1-37.el7_0")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsmbclient / libsmbclient-devel / libwbclient / libwbclient-devel / etc");
  }
}
