#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2017-3511.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(96589);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/01/18 14:49:21 $");

  script_cve_id("CVE-2016-8867", "CVE-2016-9962");

  script_name(english:"Oracle Linux 6 / 7 : docker-engine / docker-engine-selinux (ELSA-2017-3511)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

docker-engine
[1.12.6-1.0.1]
- Enable configuration of Docker daemon via sysconfig [orabug 21804877]
- Require UEK4 for docker 1.9 [orabug 22235639 22235645]
- Add docker.conf for prelink [orabug 25147708]

[1.12.6]
- the systemd unit file (/usr/lib/systemd/system/docker.service) 
contains local changes, or
- a systemd drop-in file is present, and contains -H fd:// in the 
ExecStart directive
- Backup the current version of the unit file, and replace the file with the
- Remove the Requires=docker.socket directive from the 
/usr/lib/systemd/system/docker.service file if present
- Remove -H fd:// from the ExecStart directive (both in the main unit 
file, and in any drop-in files present).
- Fix runC privilege escalation (CVE-2016-9962)

[1.12.5]
- the systemd unit file (/usr/lib/systemd/system/docker.service) 
contains local changes, or
- a systemd drop-in file is present, and contains -H fd:// in the 
ExecStart directive
- Backup the current version of the unit file, and replace the file with the
- Remove the Requires=docker.socket directive from the 
/usr/lib/systemd/system/docker.service file if present
- Remove -H fd:// from the ExecStart directive (both in the main unit 
file, and in any drop-in files present).
- Fix race on sending stdin close event 
[#29424](https://github.com/docker/docker/pull/29424)
- Fix panic in docker network ls when a network was created with --ipv6 
and no ipv6 --subnet in older docker versions 
[#29416](https://github.com/docker/docker/pull/29416)
- Fix compilation on Darwin 
[#29370](https://github.com/docker/docker/pull/29370)

[1.12.4]
- the systemd unit file (/usr/lib/systemd/system/docker.service) 
contains local changes, or
- a systemd drop-in file is present, and contains -H fd:// in the 
ExecStart directive
- Backup the current version of the unit file, and replace the file with the
- Remove the Requires=docker.socket directive from the 
/usr/lib/systemd/system/docker.service file if present
- Remove -H fd:// from the ExecStart directive (both in the main unit 
file, and in any drop-in files present).
- Fix issue where volume metadata was not removed 
[#29083](https://github.com/docker/docker/pull/29083)
- Asynchronously close streams to prevent holding container lock 
[#29050](https://github.com/docker/docker/pull/29050)
- Fix selinux labels for newly created container volumes 
[#29050](https://github.com/docker/docker/pull/29050)
- Remove hostname validation 
[#28990](https://github.com/docker/docker/pull/28990)
- Fix deadlocks caused by IO races 
[#29095](https://github.com/docker/docker/pull/29095) 
[#29141](https://github.com/docker/docker/pull/29141)
- Return an empty stats if the container is restarting 
[#29150](https://github.com/docker/docker/pull/29150)
- Fix volume store locking 
[#29151](https://github.com/docker/docker/pull/29151)
- Ensure consistent status code in API 
[#29150](https://github.com/docker/docker/pull/29150)
- Fix incorrect opaque directory permission in overlay2 
[#29093](https://github.com/docker/docker/pull/29093)
- Detect plugin content and error out on docker pull 
[#29297](https://github.com/docker/docker/pull/29297)
- Update Swarmkit [#29047](https://github.com/docker/docker/pull/29047)
- orchestrator/global: Fix deadlock on updates 
[docker/swarmkit#1760](https://github.com/docker/swarmkit/pull/1760)
- on leader switchover preserve the vxlan id for existing networks 
[docker/swarmkit#1773](https://github.com/docker/swarmkit/pull/1773)
- Refuse swarm spec not named 'default' 
[#29152](https://github.com/docker/docker/pull/29152)
- Update libnetwork 
[#29004](https://github.com/docker/docker/pull/29004) 
[#29146](https://github.com/docker/docker/pull/29146)
- Fix panic in embedded DNS 
[docker/libnetwork#1561](https://github.com/docker/libnetwork/pull/1561)
- Fix unmarhalling panic when passing --link-local-ip on global scope 
network 
[docker/libnetwork#1564](https://github.com/docker/libnetwork/pull/1564)
- Fix panic when network plugin returns nil StaticRoutes 
[docker/libnetwork#1563](https://github.com/docker/libnetwork/pull/1563)
- Fix panic in osl.(*networkNamespace).DeleteNeighbor 
[docker/libnetwork#1555](https://github.com/docker/libnetwork/pull/1555)
- Fix panic in swarm networking concurrent map read/write 
[docker/libnetwork#1570](https://github.com/docker/libnetwork/pull/1570)
- Allow encrypted networks when running docker inside a container 
[docker/libnetwork#1502](https://github.com/docker/libnetwork/pull/1502)
- Do not block autoallocation of IPv6 pool 
[docker/libnetwork#1538](https://github.com/docker/libnetwork/pull/1538)
- Set timeout for netlink calls 
[docker/libnetwork#1557](https://github.com/docker/libnetwork/pull/1557)
- Increase networking local store timeout to one minute 
[docker/libkv#140](https://github.com/docker/libkv/pull/140)
- Fix a panic in libnetwork.(*sandbox).execFunc 
[docker/libnetwork#1556](https://github.com/docker/libnetwork/pull/1556)
- Honor icc=false for internal networks 
[docker/libnetwork#1525](https://github.com/docker/libnetwork/pull/1525)
- Update syslog log driver 
[#29150](https://github.com/docker/docker/pull/29150)
- Run 'dnf upgrade' before installing in fedora 
[#29150](https://github.com/docker/docker/pull/29150)
- Add build-date back to RPM packages 
[#29150](https://github.com/docker/docker/pull/29150)
- deb package filename changed to include distro to distinguish between 
distro code names [#27829](https://github.com/docker/docker/pull/27829)

[1.12.3]
- the systemd unit file (/usr/lib/systemd/system/docker.service) 
contains local changes, or
- a systemd drop-in file is present, and contains -H fd:// in the 
ExecStart directive
- Backup the current version of the unit file, and replace the file with the
- Remove the Requires=docker.socket directive from the 
/usr/lib/systemd/system/docker.service file if present
- Remove -H fd:// from the ExecStart directive (both in the main unit 
file, and in any drop-in files present).
- Fix ambient capability usage in containers (CVE-2016-8867) 
[#27610](https://github.com/docker/docker/pull/27610)
- Prevent a deadlock in libcontainerd for Windows 
[#27136](https://github.com/docker/docker/pull/27136)
- Fix error reporting in CopyFileWithTar 
[#27075](https://github.com/docker/docker/pull/27075)
- Reset health status to starting when a container is restarted 
[#27387](https://github.com/docker/docker/pull/27387)
- Properly handle shared mount propagation in storage directory 
[#27609](https://github.com/docker/docker/pull/27609)
- Fix docker exec [#27610](https://github.com/docker/docker/pull/27610)
- Fix backward compatibility with containerd&rsquo s events log 
[#27693](https://github.com/docker/docker/pull/27693)
- Fix conversion of restart-policy 
[#27062](https://github.com/docker/docker/pull/27062)
- Update Swarmkit [#27554](https://github.com/docker/docker/pull/27554)
- Avoid restarting a task that has already been restarted 
[docker/swarmkit#1305](https://github.com/docker/swarmkit/pull/1305)
- Allow duplicate published ports when they use different protocols 
[docker/swarmkit#1632](https://github.com/docker/swarmkit/pull/1632)
- Allow multiple randomly assigned published ports on service 
[docker/swarmkit#1657](https://github.com/docker/swarmkit/pull/1657)
- Fix panic when allocations happen at init time 
[docker/swarmkit#1651](https://github.com/docker/swarmkit/pull/1651)
- Update libnetwork [#27559](https://github.com/docker/docker/pull/27559)
- Fix race in serializing sandbox to string 
[docker/libnetwork#1495](https://github.com/docker/libnetwork/pull/1495)
- Fix race during deletion 
[docker/libnetwork#1503](https://github.com/docker/libnetwork/pull/1503)
- Reset endpoint port info on connectivity revoke in bridge driver 
[docker/libnetwork#1504](https://github.com/docker/libnetwork/pull/1504)
- Fix a deadlock in networking code 
[docker/libnetwork#1507](https://github.com/docker/libnetwork/pull/1507)
- Fix a race in load balancer state 
[docker/libnetwork#1512](https://github.com/docker/libnetwork/pull/1512)
- Update fluent-logger-golang to v1.2.1 
[#27474](https://github.com/docker/docker/pull/27474)
- Update buildtags for armhf ubuntu-trusty 
[#27327](https://github.com/docker/docker/pull/27327)
- Add AppArmor to runc buildtags for armhf 
[#27421](https://github.com/docker/docker/pull/27421)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2017-January/006647.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2017-January/006648.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected docker-engine and / or docker-engine-selinux
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:docker-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:docker-engine-selinux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6 / 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL6", cpu:"x86_64", reference:"docker-engine-1.12.6-1.0.1.el6")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"docker-engine-1.12.6-1.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"docker-engine-selinux-1.12.6-1.0.1.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "docker-engine / docker-engine-selinux");
}
