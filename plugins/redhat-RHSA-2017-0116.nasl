#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0116. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96596);
  script_version("$Revision: 3.4 $");
  script_cvs_date("$Date: 2017/03/07 17:25:24 $");

  script_cve_id("CVE-2016-9962");
  script_osvdb_id(149949);
  script_xref(name:"RHSA", value:"2017:0116");

  script_name(english:"RHEL 7 : docker (RHSA-2017:0116)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for docker is now available for Red Hat Enterprise Linux 7
Extras.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Docker is an open source engine that automates the deployment of any
application as a lightweight, portable, self-sufficient container that
will run virtually anywhere.

The following packages have been upgraded to a newer upstream version:
docker (1.12.5). (BZ#1404298)

Security Fix(es) :

* The runc component used by `docker exec` feature of docker allowed
additional container processes via to be ptraced by the pid 1 of the
container. This allows the main processes of the container, if running
as root, to gain low-level access to these new processes during
initialization. An attacker can, depending on the nature of the
incoming process, leverage this to elevate access to the host. This
ranges from accessing host content through the file descriptors of the
incoming process to, potentially, a complete container escape by
leveraging memory access or syscall interception. (CVE-2016-9962)

Red Hat would like to thank the Docker project for reporting this
issue. Upstream acknowledges Aleksa Sarai (SUSE) and Tonis Tiigi
(Docker) as the original reporters.

Bug Fix(es) :

* The docker containers and images did not read proxy variables from
the environment when contacting registries. As a consequence, a user
could not pull image when the system was configured to use a proxy.
The containers and images have been fixed to read proxy variables from
the environment, and pulling images now from a system with a proxy
works correctly. (BZ#1393816)

* Occasionally the docker-storage-setup service could start before a
thin pool is ready which caused it to failed. As a consequence, the
docker daemon also failed. This bug has been fixed and now
docker-storage-setup waits for a thin pool to be created for 60
seconds. This default time can be configured. As a result, docker and
docker-storage-setup start correctly upon reboot. (BZ#1316786)

* Previously, the docker daemon's unit file was not supplying the
userspace proxy path. As a consequence, containers that exposed ports
could not be started. To fix this bug, the unit file was updated to
include the userspace proxy path option to the daemon start command,
along with several other minor packaging fixes. As a result,
containers that expose ports can now be started as expected.
(BZ#1406460)

* Previously, the system CA (Certificate Authority) pool was excluded
when the registry CA is used from the /etc/docker/certs.d/ directory.
As a consequence, pulling images failed with the following error :

Failed to push image: x509: certificate signed by unknown authority

This bug has been fixed and docker now reads the system CA pool
correctly and pulling images now work correctly. (BZ#1400372)

* Previously, the docker daemon option did not handle correctly the
'--block-registry docker.io' option. As a consequence, docker allowed
pulling images from docker.io even when the '--block-registry
docker.io' option was enabled. This update fixed the handling of the
option, and now using '--block-registry docker.io' correctly blocks
image pulling. (BZ#1395401)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-9962.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/vulnerabilities/cve-2016-9962"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2017-0116.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:container-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:docker-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:docker-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:docker-logrotate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:docker-lvm-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:docker-novolume-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:docker-rhel-push-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:docker-v1.10-migrator");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:0116";
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
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"container-selinux-1.12.5-14.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"docker-1.12.5-14.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"docker-client-1.12.5-14.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"docker-common-1.12.5-14.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"docker-logrotate-1.12.5-14.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"docker-lvm-plugin-1.12.5-14.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"docker-novolume-plugin-1.12.5-14.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"docker-rhel-push-plugin-1.12.5-14.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"docker-v1.10-migrator-1.12.5-14.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "container-selinux / docker / docker-client / docker-common / etc");
  }
}
