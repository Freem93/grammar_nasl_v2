#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:706 and 
# CentOS Errata and Security Advisory 2005:706 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21851);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2005-2097");
  script_osvdb_id(18666);
  script_xref(name:"RHSA", value:"2005:706");

  script_name(english:"CentOS 3 / 4 : cups (CESA-2005:706)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated CUPS packages that fix a security issue are now available for
Red Hat Enterprise Linux.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Common UNIX Printing System (CUPS) provides a portable printing
layer for UNIX(R) operating systems.

When processing a PDF file, bounds checking was not correctly
performed on some fields. This could cause the pdftops filter (running
as user 'lp') to crash. The Common Vulnerabilities and Exposures
project has assigned the name CVE-2005-2097 to this issue.

All users of CUPS should upgrade to these erratum packages, which
contain a patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012016.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?237defb1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012017.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1aebef10"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012037.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?efdd032b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012038.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c2f8047a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012039.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?55548d2e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012040.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5675b9e6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cups packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/09");
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
if (rpm_check(release:"CentOS-3", reference:"cups-1.1.17-13.3.31")) flag++;
if (rpm_check(release:"CentOS-3", reference:"cups-devel-1.1.17-13.3.31")) flag++;
if (rpm_check(release:"CentOS-3", reference:"cups-libs-1.1.17-13.3.31")) flag++;

if (rpm_check(release:"CentOS-4", reference:"cups-1.1.22-0.rc1.9.7")) flag++;
if (rpm_check(release:"CentOS-4", reference:"cups-devel-1.1.22-0.rc1.9.7")) flag++;
if (rpm_check(release:"CentOS-4", reference:"cups-libs-1.1.22-0.rc1.9.7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
