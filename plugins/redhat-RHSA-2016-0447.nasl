#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0447. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89983);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2017/01/10 20:34:12 $");

  script_cve_id("CVE-2015-7560");
  script_osvdb_id(135621);
  script_xref(name:"RHSA", value:"2016:0447");

  script_name(english:"RHEL 7 : Storage Server (RHSA-2016:0447)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated samba packages that fix one security issue and one bug are now
available for Red Hat Gluster Storage 3.1 for Red Hat Enterprise Linux
6 and 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Samba is an open source implementation of the Server Message Block
(SMB) or Common Internet File System (CIFS) protocol, which allows
PC-compatible machines to share files, printers, and other
information.

A flaw was found in the way Samba handled ACLs on symbolic links. An
authenticated user could use this flaw to gain access to an arbitrary
file or directory by overwriting its ACL. (CVE-2015-7560)

Red Hat would like to thank the Samba project for reporting this
issue. Upstream acknowledges Jeremy Allison (Google) and the Samba
team as the original reporters.

This update also fixes the following bug :

* Under a high load, the vfs_glusterfs AIO code would hit a
use-after-free error and cause a crash. This update fixes the affected
code, and crashes no longer occur. (BZ #1315736)

All samba users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing this update, the smb service will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-7560.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2016-0447.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ctdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ctdb-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-client-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-dc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-test-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-test-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-vfs-glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-modules");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2016:0447";
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

  if (! (rpm_exists(release:"RHEL7", rpm:"glusterfs-server"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Storage Server");

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ctdb-4.2.4-15.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ctdb-devel-4.2.4-15.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ctdb-tests-4.2.4-15.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libsmbclient-4.2.4-15.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libsmbclient-devel-4.2.4-15.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libwbclient-4.2.4-15.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libwbclient-devel-4.2.4-15.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-4.2.4-15.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-client-4.2.4-15.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-client-libs-4.2.4-15.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"samba-common-4.2.4-15.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-common-libs-4.2.4-15.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-common-tools-4.2.4-15.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-dc-4.2.4-15.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-dc-libs-4.2.4-15.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-devel-4.2.4-15.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-libs-4.2.4-15.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"samba-pidl-4.2.4-15.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-python-4.2.4-15.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-test-4.2.4-15.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-test-devel-4.2.4-15.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-test-libs-4.2.4-15.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-vfs-glusterfs-4.2.4-15.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-winbind-4.2.4-15.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-winbind-clients-4.2.4-15.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-winbind-krb5-locator-4.2.4-15.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"samba-winbind-modules-4.2.4-15.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ctdb / ctdb-devel / ctdb-tests / libsmbclient / libsmbclient-devel / etc");
  }
}
