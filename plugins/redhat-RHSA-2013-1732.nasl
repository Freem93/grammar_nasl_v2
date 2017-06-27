#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1732. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71018);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/01/05 16:29:44 $");

  script_cve_id("CVE-2013-1813");
  script_bugtraq_id(58249);
  script_osvdb_id(90748);
  script_xref(name:"RHSA", value:"2013:1732");

  script_name(english:"RHEL 6 : busybox (RHSA-2013:1732)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated busybox packages that fix one security issue and several bugs
are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

BusyBox provides a single binary that includes versions of a large
number of system commands, including a shell. This can be very useful
for recovering from certain types of system failures, particularly
those involving broken shared libraries.

It was found that the mdev BusyBox utility could create certain
directories within /dev with world-writable permissions. A local
unprivileged user could use this flaw to manipulate portions of the
/dev directory tree. (CVE-2013-1813)

This update also fixes the following bugs :

* Previously, due to a too eager string size optimization on the IBM
System z architecture, the 'wc' BusyBox command failed after
processing standard input with the following error :

wc: : No such file or directory

This bug was fixed by disabling the string size optimization and the
'wc' command works properly on IBM System z architectures. (BZ#820097)

* Prior to this update, the 'mknod' command was unable to create
device nodes with a major or minor number larger than 255.
Consequently, the kdump utility failed to handle such a device. The
underlying source code has been modified, and it is now possible to
use the 'mknod' command to create device nodes with a major or minor
number larger than 255. (BZ#859817)

* If a network installation from an NFS server was selected, the
'mount' command used the UDP protocol by default. If only TCP mounts
were supported by the server, this led to a failure of the mount
command. As a result, Anaconda could not continue with the
installation. This bug is now fixed and NFS mount operations default
to the TCP protocol. (BZ#855832)

All busybox users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1813.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1732.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected busybox and / or busybox-petitboot packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:busybox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:busybox-petitboot");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:1732";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"busybox-1.15.1-20.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"busybox-1.15.1-20.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"busybox-1.15.1-20.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"busybox-petitboot-1.15.1-20.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"busybox-petitboot-1.15.1-20.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"busybox-petitboot-1.15.1-20.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "busybox / busybox-petitboot");
  }
}
