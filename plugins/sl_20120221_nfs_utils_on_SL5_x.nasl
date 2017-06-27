#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61269);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/03/12 15:42:20 $");

  script_cve_id("CVE-2011-1749");

  script_name(english:"Scientific Linux Security Update : nfs-utils on SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The nfs-utils package provides a daemon for the kernel Network File
System (NFS) server, and related tools such as the mount.nfs,
umount.nfs, and showmount programs.

It was found that the mount.nfs tool did not handle certain errors
correctly when updating the mtab (mounted file systems table) file. A
local attacker could use this flaw to corrupt the mtab file.
(CVE-2011-1749)

This update also fixes the following bugs :

  - The nfs service failed to start if the NFSv1, NFSv2, and
    NFSv4 support was disabled (the MOUNTD_NFS_V1='no',
    MOUNTD_NFS_V2='no' MOUNTD_NFS_V3='no' lines in
    /etc/sysconfig/nfs were uncommented) because the mountd
    daemon failed to handle the settings correctly. With
    this update, the underlying code has been modified and
    the nfs service starts successfully in the described
    scenario.

  - When a user's Kerberos ticket expired, the 'sh rpc.gssd'
    messages flooded the /var/log/messages file. With this
    update, the excessive logging has been suppressed.

  - The crash simulation (SM_SIMU_CRASH) of the rpc.statd
    service had a vulnerability that could be detected by
    ISS (Internet Security Scanner). As a result, the
    rpc.statd service terminated unexpectedly with the
    following error after an ISS scan :

    rpc.statd[xxxx]: recv_rply: can't decode RPC message!
    rpc.statd[xxxx]: *** SIMULATING CRASH! ***
    rpc.statd[xxxx]: unable to register (statd, 1, udp).

However, the rpc.statd service ignored SM_SIMU_CRASH. This update
removes the simulation crash support from the service and the problem
no longer occurs.

  - The nfs-utils init scripts returned incorrect status
    codes in the following cases: if the rpcgssd and
    rpcsvcgssd daemon were not configured, were provided an
    unknown argument, their function call failed, if a
    program was no longer running and a
    /var/lock/subsys/$SERVICE file existed, if starting a
    service under an unprivileged user, if a program was no
    longer running and its pid file still existed in the
    /var/run/ directory. With this update, the correct codes
    are returned in these scenarios.

  - The 'nfsstat -m' command did not display NFSv4 mounts.
    With this update, the underlying code has been modified
    and the command returns the list of all mounts,
    including any NFSv4 mounts, as expected.

  - Previously, the nfs manual pages described the fsc mount
    option; however, this option is not supported. This
    update removes the option description from the manual
    pages.

  - The nfs-utils preinstall scriptlet failed to change the
    default group ID for the nfsnobody user to 65534. This
    update modifies the preinstall scriptlet and the default
    group ID is changed to 65534 after nfs-utils upgrade as
    expected.

  - The mount.nfs command with the '-o retry' option did not
    try to mount for the time specified in the 'retry=X'
    configuration option. This occurred due to incorrect
    error handling by the command. With this update, the
    underlying code has been fixed and the '-o retry' option
    works as expected.

In addition, this update adds the following enhancement :

  - The noresvport option, which allows NFS clients to use
    insecure ports (ports above 1023), has been added to the
    NFS server configuration options.

All nfs-utils users are advised to upgrade to this updated package,
which resolves these issues and adds this enhancement. After
installing this update, the nfs service will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1203&L=scientific-linux-errata&T=0&P=3542
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca1e5441"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nfs-utils and / or nfs-utils-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"nfs-utils-1.0.9-60.el5")) flag++;
if (rpm_check(release:"SL5", reference:"nfs-utils-debuginfo-1.0.9-60.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
