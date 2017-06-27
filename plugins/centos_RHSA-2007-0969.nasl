#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0969 and 
# CentOS Errata and Security Advisory 2007:0969 respectively.
#

include("compat.inc");

if (description)
{
  script_id(36400);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/05/19 23:34:17 $");

  script_cve_id("CVE-2007-5191");
  script_osvdb_id(40912);
  script_xref(name:"RHSA", value:"2007:0969");

  script_name(english:"CentOS 3 / 4 : util-linux (CESA-2007:0969)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated util-linux packages that fix a security issue are now
available for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The util-linux package contains a large variety of low-level system
utilities that are necessary for a Linux system to function.

A flaw was discovered in the way that the mount and umount utilities
used the setuid and setgid functions, which could lead to privileges
being dropped improperly. A local user could use this flaw to run
mount helper applications such as, mount.nfs, with additional
privileges (CVE-2007-5191).

Users are advised to update to these erratum packages which contain a
backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-November/014434.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d7465559"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-November/014435.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1c9ecc08"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-November/014436.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?429d0df7"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-November/014445.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6ee126f9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected util-linux packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:losetup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:util-linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"losetup-2.11y-31.24")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mount-2.11y-31.24")) flag++;
if (rpm_check(release:"CentOS-3", reference:"util-linux-2.11y-31.24")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"util-linux-2.12a-17.c4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
