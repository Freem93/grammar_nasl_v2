#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1213 and 
# CentOS Errata and Security Advisory 2013:1213 respectively.
#

include("compat.inc");

if (description)
{
  script_id(69791);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/05/02 10:37:32 $");

  script_cve_id("CVE-2013-4169");
  script_xref(name:"RHSA", value:"2013:1213");

  script_name(english:"CentOS 5 : gdm / initscripts (CESA-2013:1213)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gdm and initscripts packages that fix one security issue are
now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The GNOME Display Manager (GDM) provides the graphical login screen,
shown shortly after boot up, log out, and when user-switching.

A race condition was found in the way GDM handled the X server sockets
directory located in the system temporary directory. An unprivileged
user could use this flaw to perform a symbolic link attack, giving
them write access to any file, allowing them to escalate their
privileges to root. (CVE-2013-4169)

Note that this erratum includes an updated initscripts package. To fix
CVE-2013-4169, the vulnerable code was removed from GDM and the
initscripts package was modified to create the affected directory
safely during the system boot process. Therefore, this update will
appear on all systems, however systems without GDM installed are not
affected by this flaw.

Red Hat would like to thank the researcher with the nickname vladz for
reporting this issue.

All users should upgrade to these updated packages, which correct this
issue. The system must be rebooted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-September/019925.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1a6e85be"
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-September/019926.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3afeec6f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gdm and / or initscripts packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdm-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:initscripts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"gdm-2.16.0-59.el5.centos.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"gdm-docs-2.16.0-59.el5.centos.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"initscripts-8.45.42-2.el5.centos.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
