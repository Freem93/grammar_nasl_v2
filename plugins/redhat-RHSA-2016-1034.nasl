#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1034. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91115);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2017/01/10 20:34:13 $");

  script_cve_id("CVE-2016-3697");
  script_osvdb_id(137605);
  script_xref(name:"RHSA", value:"2016:1034");

  script_name(english:"RHEL 7 : docker (RHSA-2016:1034)");
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

Security Fix(es) :

* It was found that Docker would launch containers under the specified
UID instead of a username. An attacker able to launch a container
could use this flaw to escalate their privileges to root within the
launched container. (CVE-2016-3697)

This issue was discovered by Mrunal Patel (Red Hat).

Bug Fix(es) :

* The process of pulling an image spawns a new 'goroutine' for each
layer in the image manifest. If any of these downloads, everything
stops and an error is returned, even though other goroutines would
still be running and writing output through a progress reader which is
attached to an http response writer. Since the request handler had
already returned from the first error, the http server panics when one
of these download goroutines makes a write to the response writer
buffer. This bug has been fixed, and docker no longer panics when
pulling an image. (BZ#1264562)

* Previously, in certain situations, a container rootfs remained busy
during container removal. This typically happened if a container mount
point leaked into another mount namespace. As a consequence, container
removal failed. To fix this bug, a new docker daemon option
'dm.use_deferred_deletion' has been provided. If set to true, this
option will defer the container rootfs deletion. The user will see
success on container removal but the actual thin device backing the
rootfs will be deleted later when it is not busy anymore. (BZ#1190492)

* Previously, the Docker unit file had the 'Restart' option set to
'on-failure'. Consequently, the docker daemon was forced to restart
even in cases where it couldn't be started because of configuration or
other issues and this situation forced unnecessary restarts of the
docker-storage-setup service in a loop. This also caused real error
messages to be lost due to so many restarts. To fix this bug,
'Restart=on-failure' has been replaced with 'Restart=on-abnormal' in
the docker unit file. As a result, the docker daemon will not
automatically restart if it fails with an unclean exit code.
(BZ#1319783)

* Previously, the request body was incorrectly read twice by the
docker daemon and consequently, an EOF error was returned. To fix this
bug, the code which incorrectly read the request body the first time
has been removed. As a result, the EOF error is no longer returned and
the body is correctly read when really needed. (BZ#1329743)

Enhancement(s) :

* The /usr/bin/docker script now calls /usr/bin/docker-current or
/usr/bin/docker-latest based on the value of the sysconfig variable
DOCKERBINARY present in /etc/sysconfig/docker. /usr/bin/docker and
/etc/sysconfig/docker provided by the docker-common package allow the
admin to configure which docker client binary gets called.
/usr/bin/docker will call /usr/bin/docker-latest by default when
docker is not installed. If docker is installed, /usr/bin/docker will
call /usr/bin/docker-current by default, unless DOCKERBINARY is set to
/usr/bin/docker-latest in /etc/sysconfig/docker. This way, you can use
docker-latest or docker without the need to check which version of the
daemon is currently running. (BZ#1328219)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-3697.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2016-1034.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:docker-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:docker-forward-journald");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:docker-logrotate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:docker-selinux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/13");
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
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:1034";
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
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"docker-1.9.1-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"docker-common-1.9.1-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"docker-forward-journald-1.9.1-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"docker-logrotate-1.9.1-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"docker-selinux-1.9.1-40.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "docker / docker-common / docker-forward-journald / docker-logrotate / etc");
  }
}
