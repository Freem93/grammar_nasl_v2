#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0310. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58064);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2017/01/05 16:04:21 $");

  script_cve_id("CVE-2011-1749");
  script_bugtraq_id(47532);
  script_osvdb_id(74350);
  script_xref(name:"RHSA", value:"2012:0310");

  script_name(english:"RHEL 5 : nfs-utils (RHSA-2012:0310)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated nfs-utils package that fixes one security issue, various
bugs, and adds one enhancement is now available for Red Hat Enterprise
Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The nfs-utils package provides a daemon for the kernel Network File
System (NFS) server, and related tools such as the mount.nfs,
umount.nfs, and showmount programs.

It was found that the mount.nfs tool did not handle certain errors
correctly when updating the mtab (mounted file systems table) file. A
local attacker could use this flaw to corrupt the mtab file.
(CVE-2011-1749)

This update also fixes the following bugs :

* The nfs service failed to start if the NFSv1, NFSv2, and NFSv4
support was disabled (the MOUNTD_NFS_V1='no', MOUNTD_NFS_V2='no'
MOUNTD_NFS_V3='no' lines in /etc/sysconfig/nfs were uncommented)
because the mountd daemon failed to handle the settings correctly.
With this update, the underlying code has been modified and the nfs
service starts successfully in the described scenario. (BZ#529588)

* When a user's Kerberos ticket expired, the 'sh rpc.gssd' messages
flooded the /var/log/messages file. With this update, the excessive
logging has been suppressed. (BZ#593097)

* The crash simulation (SM_SIMU_CRASH) of the rpc.statd service had a
vulnerability that could be detected by ISS (Internet Security
Scanner). As a result, the rpc.statd service terminated unexpectedly
with the following error after an ISS scan :

rpc.statd[xxxx]: recv_rply: can't decode RPC message! rpc.statd[xxxx]:
*** SIMULATING CRASH! *** rpc.statd[xxxx]: unable to register (statd,
1, udp).

However, the rpc.statd service ignored SM_SIMU_CRASH. This update
removes the simulation crash support from the service and the problem
no longer occurs. (BZ#600497)

* The nfs-utils init scripts returned incorrect status codes in the
following cases: if the rpcgssd and rpcsvcgssd daemon were not
configured, were provided an unknown argument, their function call
failed, if a program was no longer running and a
/var/lock/subsys/$SERVICE file existed, if starting a service under an
unprivileged user, if a program was no longer running and its pid file
still existed in the /var/run/ directory. With this update, the
correct codes are returned in these scenarios. (BZ#710020)

* The 'nfsstat -m' command did not display NFSv4 mounts. With this
update, the underlying code has been modified and the command returns
the list of all mounts, including any NFSv4 mounts, as expected.
(BZ#712438)

* Previously, the nfs manual pages described the fsc mount option;
however, this option is not supported. This update removes the option
description from the manual pages. (BZ#715523)

* The nfs-utils preinstall scriptlet failed to change the default
group ID for the nfsnobody user to 65534. This update modifies the
preinstall scriptlet and the default group ID is changed to 65534
after nfs-utils upgrade as expected. (BZ#729603)

* The mount.nfs command with the '-o retry' option did not try to
mount for the time specified in the 'retry=X' configuration option.
This occurred due to incorrect error handling by the command. With
this update, the underlying code has been fixed and the '-o retry'
option works as expected. (BZ#736677)

In addition, this update adds the following enhancement :

* The noresvport option, which allows NFS clients to use insecure
ports (ports above 1023), has been added to the NFS server
configuration options. (BZ#513094)

All nfs-utils users are advised to upgrade to this updated package,
which resolves these issues and adds this enhancement. After
installing this update, the nfs service will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1749.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-0310.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nfs-utils and / or nfs-utils-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nfs-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nfs-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/21");
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
  rhsa = "RHSA-2012:0310";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"nfs-utils-1.0.9-60.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"nfs-utils-1.0.9-60.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"nfs-utils-1.0.9-60.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"nfs-utils-debuginfo-1.0.9-60.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"nfs-utils-debuginfo-1.0.9-60.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"nfs-utils-debuginfo-1.0.9-60.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nfs-utils / nfs-utils-debuginfo");
  }
}
