#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1321 and 
# CentOS Errata and Security Advisory 2009:1321 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(43784);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/03/19 14:28:09 $");

  script_cve_id("CVE-2008-4552");
  script_bugtraq_id(31823);
  script_xref(name:"RHSA", value:"2009:1321");

  script_name(english:"CentOS 5 : nfs-utils (CESA-2009:1321)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated nfs-utils package that fixes a security issue and several
bugs is now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

The nfs-utils package provides a daemon for the kernel NFS server and
related tools.

It was discovered that nfs-utils did not use tcp_wrappers correctly.
Certain hosts access rules defined in '/etc/hosts.allow' and
'/etc/hosts.deny' may not have been honored, possibly allowing remote
attackers to bypass intended access restrictions. (CVE-2008-4552)

This updated package also fixes the following bugs :

* the 'LOCKD_TCPPORT' and 'LOCKD_UDPPORT' options in
'/etc/sysconfig/nfs' were not honored: the lockd daemon continued to
use random ports. With this update, these options are honored.
(BZ#434795)

* it was not possible to mount NFS file systems from a system that has
the '/etc/' directory mounted on a read-only file system (this could
occur on systems with an NFS-mounted root file system). With this
update, it is possible to mount NFS file systems from a system that
has '/etc/' mounted on a read-only file system. (BZ#450646)

* arguments specified by 'STATDARG=' in '/etc/sysconfig/nfs' were
removed by the nfslock init script, meaning the arguments specified
were never passed to rpc.statd. With this update, the nfslock init
script no longer removes these arguments. (BZ#459591)

* when mounting an NFS file system from a host not specified in the
NFS server's '/etc/exports' file, a misleading 'unknown host' error
was logged on the server (the hostname lookup did not fail). With this
update, a clearer error message is provided for these situations.
(BZ#463578)

* the nhfsstone benchmark utility did not work with NFS version 3 and
4. This update adds support to nhfsstone for NFS version 3 and 4. The
new nhfsstone '-2', '-3', and '-4' options are used to select an NFS
version (similar to nfsstat(8)). (BZ#465933)

* the exportfs(8) manual page contained a spelling mistake, 'djando',
in the EXAMPLES section. (BZ#474848)

* in some situations the NFS server incorrectly refused mounts to
hosts that had a host alias in a NIS netgroup. (BZ#478952)

* in some situations the NFS client used its cache, rather than using
the latest version of a file or directory from a given export. This
update adds a new mount option, 'lookupcache=', which allows the NFS
client to control how it caches files and directories. Note: The Red
Hat Enterprise Linux 5.4 kernel update (the fourth regular update)
must be installed in order to use the 'lookupcache=' option. Also,
'lookupcache=' is currently only available for NFS version 3. Support
for NFS version 4 may be introduced in future Red Hat Enterprise Linux
5 updates. Refer to Red Hat Bugzilla #511312 for further information.
(BZ#489335)

Users of nfs-utils should upgrade to this updated package, which
contains backported patches to correct these issues. After installing
this update, the nfs service will be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016147.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b9462ac4"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016148.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7a3a76b6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nfs-utils package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nfs-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"nfs-utils-1.0.9-42.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
