#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:1130 and 
# CentOS Errata and Security Advisory 2007:1130 respectively.
#

include("compat.inc");

if (description)
{
  script_id(29730);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/05/19 23:34:18 $");

  script_cve_id("CVE-2007-6239");
  script_osvdb_id(39381);
  script_xref(name:"RHSA", value:"2007:1130");

  script_name(english:"CentOS 3 / 4 / 5 : squid (CESA-2007:1130)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated squid packages that fix a security issue are now available for
Red Hat Enterprise Linux 2.1, 3, 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Squid is a high-performance proxy caching server for Web clients,
supporting FTP, gopher, and HTTP data objects.

A flaw was found in the way squid stored HTTP headers for cached
objects in system memory. An attacker could cause squid to use
additional memory, and trigger high CPU usage when processing requests
for certain cached objects, possibly leading to a denial of service.
(CVE-2007-6239)

Users of squid are advised to upgrade to these updated packages, which
contain a backported patch to resolve this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-December/014514.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e87d9a4f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-December/014515.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?02b03c0f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-December/014516.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?56ae7693"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-December/014518.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fd3cddf6"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-December/014522.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a3fb07cc"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-December/014523.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5319518a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-December/014539.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b7ab637e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-December/014540.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fe608ee3"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected squid package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:squid");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/19");
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
if (rpm_check(release:"CentOS-3", reference:"squid-2.5.STABLE3-8.3E")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"squid-2.5.STABLE14-1.4E.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"squid-2.5.STABLE14-1.4E.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"squid-2.5.STABLE14-1.4E.el4_6.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"squid-2.6.STABLE6-5.el5_1.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
