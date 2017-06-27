#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0955 and 
# CentOS Errata and Security Advisory 2009:0955 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(67064);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/06/29 00:08:47 $");

  script_cve_id("CVE-2008-1376", "CVE-2009-0180");
  script_xref(name:"RHSA", value:"2009:0955");

  script_name(english:"CentOS 4 : nfs-utils (CESA-2009:0955)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated nfs-utils package that fixes a security issue and multiple
bugs is now available for Red Hat Enterprise Linux 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The nfs-utils package provides a daemon for the kernel NFS server and
related tools, which provides a much higher level of performance than
the traditional Linux NFS server used by most users.

A flaw was found in the nfs-utils package provided by RHBA-2008:0742.
The nfs-utils package was missing TCP wrappers support, which could
result in an administrator believing they had access restrictions
enabled when they did not. (CVE-2008-1376)

This update also includes the following bug fixes :

* the 'nfsstat' command now displays correct statistics. In previous
versions, performing more than 2^31 RPC calls could cause the
'nfsstat' command to incorrectly display the number of calls as
'negative'. This was because 'nfsstat' printed statistics from
/proc/net/rpc/* files as signed integers; with this version of
nfs-utils, 'nfsstat' now reads and prints these statistics as unsigned
integers. (BZ#404831)

* imapd upcalls now support zero-length reads and perform extra bounds
checking in gssd and svcgssd. This fixes a bug in previous versions
that could cause the rpc.imapd daemon to hang when communicating with
the kernel, which would halt any ID translation services. (BZ#448710)

* tcp_wrappers supported in nfs-utils now allows proper application of
hosts access rules defined in /etc/hosts.allow and /etc/hosts.deny.
(BZ#494585)

* the nfs init script did not check whether SECURE_NFS was set to
'yes' before starting, stopping, or querying rpc.svcgssd. On systems
where SECURE_NFS was not set to 'yes', the nfs init script could not
start the rpc.svcgssd daemon at the 'service nfs start' command
because the rpcsvcssd init script would check the status of SECURE_NFS
before starting the daemon. However, at the 'service nfs stop' or
'service nfs restart' commands, nfs init script would attempt to stop
rpc.svcgssd and then report a failure because the daemon was not
running in the first place. These error messages may have misled
end-users into believing that there was a genuine problem with their
NFS configuration. This version of nfs-utils contains a fix backported
from Red Hat Enterprise Linux 5. nfs-utils now checks the status of
SECURE_NFS before the nfs init script attempts to start, query or stop
rpc.svcgssd and therefore, the irrelevant error messages seen
previously will not appear. (BZ#470423)

* the nfs init script is now fully compliant with Linux Standard Base
Core specifications. This update fixes a bug that prevented
'/etc/init.d/nfs start' from exiting properly if NFS was already
running. (BZ#474570)

* /var/lib/nfs/statd/sm is now created with the proper user and group
whenever rpc.statd is called. In previous versions, some thread stack
conditions could incorrectly prevent rpc.statd from creating the
/var/lib/nfs/statd/sm file, which could cause 'service nfslock start'
to fail. (BZ#479376)

All users of nfs-utils should upgrade to this updated package, which
resolves these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2009-May/015885.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nfs-utils package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nfs-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"nfs-utils-1.0.6-93.EL4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
