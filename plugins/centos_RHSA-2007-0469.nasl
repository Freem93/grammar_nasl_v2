#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0469 and 
# CentOS Errata and Security Advisory 2007:0469 respectively.
#

include("compat.inc");

if (description)
{
  script_id(25500);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2013/06/28 23:45:05 $");

  script_cve_id("CVE-2006-4146");
  script_osvdb_id(28318);
  script_xref(name:"RHSA", value:"2007:0469");

  script_name(english:"CentOS 3 : gdb (CESA-2007:0469)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated gdb package that fixes a security issue and various bugs is
now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

GDB, the GNU debugger, allows debugging of programs written in C, C++,
and other languages by executing them in a controlled fashion and then
printing their data.

Various buffer overflows and underflows were found in the DWARF
expression computation stack in GDB. If an attacker could trick a user
into loading an executable containing malicious debugging information
into GDB, they may be able to execute arbitrary code with the
privileges of the user. (CVE-2006-4146)

This updated package also addresses the following issues :

* Support on 64-bit hosts shared libraries debuginfo larger than 2GB.

* Fix a race occasionally leaving the detached processes stopped.

* Fix segmentation fault on the source display by ^X 1.

* Fix a crash on an opaque type dereference.

All users of gdb should upgrade to this updated package, which
contains backported patches to resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013897.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?094c649e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013918.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3fa4b952"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013919.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1e7d48f1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gdb package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"gdb-6.3.0.0-1.138.el3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
