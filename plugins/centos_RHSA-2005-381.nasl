#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:381 and 
# CentOS Errata and Security Advisory 2005:381 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21816);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2004-1287", "CVE-2005-1194");
  script_osvdb_id(12446, 16088);
  script_xref(name:"RHSA", value:"2005:381");

  script_name(english:"CentOS 3 / 4 : nasm (CESA-2005:381)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated nasm package that fixes multiple security issues is now
available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

NASM is an 80x86 assembler.

Two stack based buffer overflow bugs have been found in nasm. An
attacker could create an ASM file in such a way that when compiled by
a victim, could execute arbitrary code on their machine. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
names CVE-2004-1287 and CVE-2005-1194 to these issues.

All users of nasm are advised to upgrade to this updated package,
which contains backported fixes for these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2005-May/011626.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2005-May/011627.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2005-May/011630.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2005-May/011631.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2005-May/011635.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected nasm packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nasm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nasm-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nasm-rdoff");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/16");
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
if (rpm_check(release:"CentOS-3", reference:"nasm-0.98.35-3.EL3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"nasm-doc-0.98.35-3.EL3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"nasm-rdoff-0.98.35-3.EL3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"nasm-0.98.38-3.EL4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"nasm-doc-0.98.38-3.EL4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"nasm-rdoff-0.98.38-3.EL4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
