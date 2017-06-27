#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0913 and 
# CentOS Errata and Security Advisory 2007:0913 respectively.
#

include("compat.inc");

if (description)
{
  script_id(26077);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/11/17 20:59:08 $");

  script_cve_id("CVE-2007-3999");
  script_bugtraq_id(25534);
  script_osvdb_id(37324, 37325, 37332);
  script_xref(name:"RHSA", value:"2007:0913");
  script_xref(name:"TRA", value:"TRA-2007-07");

  script_name(english:"CentOS 4 : nfs-utils-lib (CESA-2007:0913)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated nfs-utils-lib package to correct a security flaw is now
available for Red Hat Enterprise Linux 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The nfs-utils-lib package contains support libraries that are needed
by the commands and daemons of the nfs-utils package.

Tenable Network Security discovered a stack-based buffer overflow flaw
in the RPC library used by nfs-utils-lib. A remote unauthenticated
attacker who can access an application linked against nfs-utils-lib
could trigger this flaw and cause the application to crash. On Red Hat
Enterprise Linux 4 it is not possible to exploit this flaw to run
arbitrary code as the overflow is blocked by FORTIFY_SOURCE.
(CVE-2007-3999)

Users of nfs-utils-lib are advised to upgrade to this updated package,
which contains a backported patch that resolves this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014207.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0dea39e8"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014233.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7e6c6896"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014234.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3d7c58a3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2007-07"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nfs-utils-lib packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nfs-utils-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nfs-utils-lib-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/24");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/09/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"nfs-utils-lib-1.0.6-8.z1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"nfs-utils-lib-1.0.6-8.z1.c4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"nfs-utils-lib-1.0.6-8.z1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"nfs-utils-lib-devel-1.0.6-8.z1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"nfs-utils-lib-devel-1.0.6-8.z1.c4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"nfs-utils-lib-devel-1.0.6-8.z1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
