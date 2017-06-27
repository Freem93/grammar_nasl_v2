#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60656);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:53 $");

  script_cve_id("CVE-2008-4552");

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
"It was discovered that nfs-utils did not use tcp_wrappers correctly.
Certain hosts access rules defined in '/etc/hosts.allow' and
'/etc/hosts.deny' may not have been honored, possibly allowing remote
attackers to bypass intended access restrictions. (CVE-2008-4552)

This updated package also fixes the following bugs :

  - the 'LOCKD_TCPPORT' and 'LOCKD_UDPPORT' options in
    '/etc/sysconfig/nfs' were not honored: the lockd daemon
    continued to use random ports. With this update, these
    options are honored. (BZ#434795)

  - it was not possible to mount NFS file systems from a
    system that has the '/etc/' directory mounted on a
    read-only file system (this could occur on systems with
    an NFS-mounted root file system). With this update, it
    is possible to mount NFS file systems from a system that
    has '/etc/' mounted on a read-only file system.
    (BZ#450646)

  - arguments specified by 'STATDARG=' in
    '/etc/sysconfig/nfs' were removed by the nfslock init
    script, meaning the arguments specified were never
    passed to rpc.statd. With this update, the nfslock init
    script no longer removes these arguments. (BZ#459591)

  - when mounting an NFS file system from a host not
    specified in the NFS server's '/etc/exports' file, a
    misleading 'unknown host' error was logged on the server
    (the hostname lookup did not fail). With this update, a
    clearer error message is provided for these situations.
    (BZ#463578)

  - the nhfsstone benchmark utility did not work with NFS
    version 3 and 4. This update adds support to nhfsstone
    for NFS version 3 and 4. The new nhfsstone '-2', '-3',
    and '-4' options are used to select an NFS version
    (similar to nfsstat(8)). (BZ#465933)

  - the exportfs(8) manual page contained a spelling
    mistake, 'djando', in the EXAMPLES section. (BZ#474848)

  - in some situations the NFS server incorrectly refused
    mounts to hosts that had a host alias in a NIS netgroup.
    (BZ#478952)

  - in some situations the NFS client used its cache, rather
    than using the latest version of a file or directory
    from a given export. This update adds a new mount
    option, 'lookupcache=', which allows the NFS client to
    control how it caches files and directories. Note: The
    Scientific Linux 2.6.18-164 or later kernel update must
    be installed in order to use the 'lookupcache=' option.
    Also, 'lookupcache=' is currently only available for NFS
    version 3. Support for NFS version 4 may be introduced
    in future Scientific Linux 5 updates. (BZ#489335)

After installing this update, the nfs service will be restarted
automatically.

Note: This update is already in SL 5.4"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0911&L=scientific-linux-errata&T=0&P=1589
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?96e94207"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=434795"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=450646"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=459591"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=463578"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=465933"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=474848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=478952"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=489335"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected nfs-utils, nfs-utils-lib and / or
nfs-utils-lib-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"nfs-utils-1.0.9-42.el5")) flag++;
if (rpm_check(release:"SL5", reference:"nfs-utils-lib-1.0.8-7.6.el5")) flag++;
if (rpm_check(release:"SL5", reference:"nfs-utils-lib-devel-1.0.8-7.6.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
