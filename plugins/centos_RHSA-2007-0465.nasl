#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0465 and 
# CentOS Errata and Security Advisory 2007:0465 respectively.
#

include("compat.inc");

if (description)
{
  script_id(25499);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/05/19 23:34:17 $");

  script_cve_id("CVE-2004-0813", "CVE-2007-1716");
  script_osvdb_id(10352, 37271);
  script_xref(name:"RHSA", value:"2007:0465");

  script_name(english:"CentOS 3 : pam (CESA-2007:0465)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated pam packages that resolves several bugs and security flaws are
now available for Red Hat Enterprise Linux 3.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Pluggable Authentication Modules (PAM) provide a system whereby
administrators can set up authentication policies without having to
recompile programs that handle authentication.

A flaw was found in the way the Linux kernel handled certain SG_IO
commands. Console users with access to certain device files had the
ability to damage recordable CD drives. The way pam_console handled
permissions of these files has been modified to disallow access. This
change also required modifications to the cdrecord application.
(CVE-2004-0813)

A flaw was found in the way pam_console set console device
permissions. It was possible for various console devices to retain
ownership of the console user after logging out, possibly leaking
information to an unauthorized user. (CVE-2007-1716)

The pam_unix module provides authentication against standard
/etc/passwd and /etc/shadow files. The pam_stack module provides
support for stacking PAM configuration files. Both of these modules
contained small memory leaks which caused problems in applications
calling PAM authentication repeatedly in the same process.

All users of PAM should upgrade to these updated packages, which
resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013892.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?356b8a83"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013916.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a1eedb32"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013917.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2efe6856"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected pam packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:M/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cdda2wav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cdrecord");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cdrecord-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mkisofs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pam-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/07/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"cdda2wav-2.01.0.a32-0.EL3.6")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"cdda2wav-2.01.0.a32-0.EL3.6")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"cdrecord-2.01.0.a32-0.EL3.6")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"cdrecord-2.01.0.a32-0.EL3.6")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"cdrecord-devel-2.01.0.a32-0.EL3.6")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"cdrecord-devel-2.01.0.a32-0.EL3.6")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"mkisofs-2.01.0.a32-0.EL3.6")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"mkisofs-2.01.0.a32-0.EL3.6")) flag++;
if (rpm_check(release:"CentOS-3", reference:"pam-0.75-72")) flag++;
if (rpm_check(release:"CentOS-3", reference:"pam-devel-0.75-72")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
