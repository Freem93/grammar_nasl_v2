#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0623. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81640);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/01/06 15:51:01 $");

  script_cve_id("CVE-2014-9356", "CVE-2014-9357");
  script_osvdb_id(115815, 115816);
  script_xref(name:"RHSA", value:"2015:0623");

  script_name(english:"RHEL 7 : docker (RHSA-2015:0623)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated docker packages that fix two security issues, several bugs,
and add various enhancements are now available for Red Hat Enterprise
Linux 7 Extras.

Red Hat Product Security has rated this update as having Low security
impact. Common Vulnerability Scoring System (CVSS) base scores, which
give detailed severity ratings, are available for each vulnerability
from the CVE links in the References section.

Docker is a service providing container management on Linux.

It was found that a malicious container image could overwrite
arbitrary portions of the host file system by including absolute
symlinks, potentially leading to privilege escalation. (CVE-2014-9356)

A flaw was found in the way the Docker service unpacked images or
builds after a 'docker pull'. An attacker could use this flaw to
provide a malicious image or build that, when unpacked, would escalate
their privileges on the system. (CVE-2014-9357)

Red Hat would like to thank Docker Inc. for reporting these issues.

The docker-python subpackage provides the new Atomic tool. The goal of
Atomic is to provide a high level, coherent entry point for Red Hat
Enterprise Linux Atomic Host. Atomic makes it easier to interact with
special kinds of containers, such as super-privileged debugging tools.
Comprehensive information and documentation is available in the atomic
manual pages.

The docker packages have been upgraded to upstream version 1.4.1,
which provides a number of bug fixes and enhancements over the
previous version, most notably an experimental overlayfs storage
driver. (BZ#1174351)

Bug fixes :

* The JSON configuration files for containers and images were
inconsistent. As a consequence, when these files were parsed by the
'docker inspect' command, the output was unnecessarily complex. This
update improves the key naming schema in the configuration files and
the output from 'docker inspect' is now uniform. (BZ#1092773)

* The /run directory had an incorrect SELinux label. As a consequence,
containers could not access /run. This update corrects the SELinux
label and containers now have access to /run. (BZ#1100009)

* The Docker service contained an incorrect path for the secrets
directory. As a consequence, executing 'docker run' failed to create
containers. This update fixes the default path to the secrets
directory and 'docker run' now executes successfully. (BZ#1102568)

* It was not possible to specify a default repository in the
configuration file in cases where all docker.io files are
inaccessible. As a consequence, running docker commands failed because
they could not contact the default repositories. Now, it is possible
to specify a local Docker repository, and commands no longer fail
because they are able to connect to a local private repository.
(BZ#1106430)

* When executing the 'docker attach' command on a container which was
in the process of shutting down, the process did not fail, but became
unresponsive. This bug has been fixed, and running 'docker attach' on
a container which is shutting down causes the attach process to fail
with an informative error message that it is not possible to attach to
a stopped container. (BZ#1113608)

* The 'docker run' sub-command incorrectly returned non-zero exit
codes, when they all should have been zero. As a consequence, it was
not possible to differentiate between the exit codes of the docker
command line and exit codes of contained processes, which in turn made
automated control of 'docker run' impossible. This update fixes the
inconsistencies within the exit codes of 'docker run'. Additionally,
this update also fixes inconsistencies of other docker sub-commands
and improves the language in the error and warning messages.
(BZ#1162807)

* Adding a new registry with the '--registry-prepend' option did not
follow the correct order to query and download an image. As a
consequence, it did not query the prepended new registry first, but
rather started with querying docker.io. The '--registry-prepend'
option has been renamed to '--registry-add' and its behavior has been
changed to query the registries added in the given order, with
docker.io queried last. (BZ#1186153)

All docker users are advised to upgrade to these updated packages,
which correct these issues and add these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-9356.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-9357.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-0623.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:docker-logrotate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:docker-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-websocket-client");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:0623";
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
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"docker-1.4.1-37.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"docker-logrotate-1.4.1-37.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"docker-python-0.7.1-37.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-websocket-client-0.14.1-37.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "docker / docker-logrotate / docker-python / python-websocket-client");
  }
}
