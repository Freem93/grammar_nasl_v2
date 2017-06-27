#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0955. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38816);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2017/01/03 17:27:01 $");

  script_cve_id("CVE-2008-1376", "CVE-2009-0180");
  script_xref(name:"RHSA", value:"2009:0955");

  script_name(english:"RHEL 4 : nfs-utils (RHSA-2009:0955)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
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
    value:"https://www.redhat.com/security/data/cve/CVE-2008-1376.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-0955.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nfs-utils package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nfs-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2009:0955";
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
  if (rpm_check(release:"RHEL4", reference:"nfs-utils-1.0.6-93.EL4")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nfs-utils");
  }
}
