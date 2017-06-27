#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0765 and 
# CentOS Errata and Security Advisory 2007:0765 respectively.
#

include("compat.inc");

if (description)
{
  script_id(25849);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/05/19 23:34:17 $");

  script_cve_id("CVE-2007-0235");
  script_osvdb_id(32815);
  script_xref(name:"RHSA", value:"2007:0765");

  script_name(english:"CentOS 4 : libgtop2 (CESA-2007:0765)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated libgtop2 package that fixes a security issue and a
functionality bug is now available for Red Hat Enterprise Linux 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The libgtop2 package contains a library for obtaining information
about a running system, such as cpu, memory and disk usage; active
processes; and PIDs.

A flaw was found in the way libgtop2 handled long filenames mapped
into the address space of a process. An attacker could execute
arbitrary code on behalf of the user running gnome-system-monitor by
executing a process and mapping a file with a specially crafted name
into the processes' address space. (CVE-2007-0235)

This update also fixes the following bug :

* when a version of libgtop2 compiled to run on a 32-bit architecture
was used to inspect a process running in 64-bit mode, it failed to
report certain information regarding address space mapping correctly.

All users of gnome-system-monitor are advised to upgrade to this
updated libgtop2 package, which contains backported patches that
resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-August/014136.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f3b6893d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-August/014141.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aab82581"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-August/014142.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1cca6966"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libgtop2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgtop2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgtop2-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/08/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/14");
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
if (rpm_check(release:"CentOS-4", reference:"libgtop2-2.8.0-1.0.2")) flag++;
if (rpm_check(release:"CentOS-4", reference:"libgtop2-devel-2.8.0-1.0.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
