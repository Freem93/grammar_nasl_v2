#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:387 and 
# CentOS Errata and Security Advisory 2005:387 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21817);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2005-0753");
  script_osvdb_id(15670, 15671);
  script_xref(name:"RHSA", value:"2005:387");

  script_name(english:"CentOS 3 / 4 : cvs (CESA-2005:387)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated cvs package that fixes security bugs is now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

CVS (Concurrent Version System) is a version control system.

A buffer overflow bug was found in the way the CVS client processes
version and author information. If a user can be tricked into
connecting to a malicious CVS server, an attacker could execute
arbitrary code. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-0753 to this issue.

Additionally, a bug was found in which CVS freed an invalid pointer.
However, this issue does not appear to be exploitable.

All users of cvs should upgrade to this updated package, which
includes a backported patch to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011594.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f5f381d1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011595.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5d5640db"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011596.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?42ac4379"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011597.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?10cf9e20"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011598.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0851da05"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cvs package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cvs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/18");
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
if (rpm_check(release:"CentOS-3", reference:"cvs-1.11.2-27")) flag++;

if (rpm_check(release:"CentOS-4", reference:"cvs-1.11.17-7.RHEL4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
