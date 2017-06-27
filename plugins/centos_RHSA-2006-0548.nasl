#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0548 and 
# CentOS Errata and Security Advisory 2006:0548 respectively.
#

include("compat.inc");

if (description)
{
  script_id(22002);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2006-2449");
  script_osvdb_id(26511);
  script_xref(name:"RHSA", value:"2006:0548");

  script_name(english:"CentOS 4 : kdebase (CESA-2006:0548)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kdebase packages that correct a security flaw in kdm are now
available for Red Hat Enterprise Linux 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kdebase packages provide the core applications for KDE, the K
Desktop Environment. These core packages include the KDE Display
Manager (KDM).

Ludwig Nussel discovered a flaw in KDM. A malicious local KDM user
could use a symlink attack to read an arbitrary file that they would
not normally have permissions to read. (CVE-2006-2449)

Note: this issue does not affect the version of KDM as shipped with
Red Hat Enterprise Linux 2.1 or 3.

All users of KDM should upgrade to these updated packages which
contain a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-June/012968.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?025f80d1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-June/012969.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4c7acca1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-June/012975.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c99d83cc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdebase packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdebase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdebase-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"kdebase-3.3.1-5.12")) flag++;
if (rpm_check(release:"CentOS-4", reference:"kdebase-devel-3.3.1-5.12")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
