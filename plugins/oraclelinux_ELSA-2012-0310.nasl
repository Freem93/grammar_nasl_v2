#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2012:0310 and 
# Oracle Linux Security Advisory ELSA-2012-0310 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68481);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/06 17:02:14 $");

  script_cve_id("CVE-2011-1749");
  script_bugtraq_id(47532);
  script_osvdb_id(74350);
  script_xref(name:"RHSA", value:"2012:0310");

  script_name(english:"Oracle Linux 5 : nfs-utils (ELSA-2012-0310)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2012:0310 :

An updated nfs-utils package that fixes one security issue, various
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
    value:"https://oss.oracle.com/pipermail/el-errata/2012-March/002661.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nfs-utils package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nfs-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"nfs-utils-1.0.9-60.0.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nfs-utils");
}
