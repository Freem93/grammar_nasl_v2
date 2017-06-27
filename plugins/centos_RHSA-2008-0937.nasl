#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0937 and 
# CentOS Errata and Security Advisory 2008:0937 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(34375);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/17 20:59:09 $");

  script_cve_id("CVE-2008-3639", "CVE-2008-3640", "CVE-2008-3641", "CVE-2009-0577");
  script_osvdb_id(49131, 49132);
  script_xref(name:"RHSA", value:"2008:0937");

  script_name(english:"CentOS 3 / 4 / 5 : cups (CESA-2008:0937)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated cups packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Common UNIX Printing System (CUPS) provides a portable printing
layer for UNIX(R) operating systems.

A buffer overflow flaw was discovered in the SGI image format decoding
routines used by the CUPS image converting filter 'imagetops'. An
attacker could create a malicious SGI image file that could, possibly,
execute arbitrary code as the 'lp' user if the file was printed.
(CVE-2008-3639)

An integer overflow flaw leading to a heap buffer overflow was
discovered in the Text-to-PostScript 'texttops' filter. An attacker
could create a malicious text file that could, possibly, execute
arbitrary code as the 'lp' user if the file was printed.
(CVE-2008-3640)

An insufficient buffer bounds checking flaw was discovered in the
HP-GL/2-to-PostScript 'hpgltops' filter. An attacker could create a
malicious HP-GL/2 file that could, possibly, execute arbitrary code as
the 'lp' user if the file was printed. (CVE-2008-3641)

Red Hat would like to thank regenrecht for reporting these issues.

All CUPS users are advised to upgrade to these updated packages, which
contain backported patches to resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-October/015312.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?78130a2f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-October/015313.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?964e8d00"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-October/015314.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?75ae72da"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-October/015316.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4bdb80d5"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-October/015324.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?14755539"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-October/015325.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bdfcf9c2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-October/015330.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1e3642cb"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-October/015331.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0236902b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cups packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-lpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"cups-1.1.17-13.3.54")) flag++;
if (rpm_check(release:"CentOS-3", reference:"cups-devel-1.1.17-13.3.54")) flag++;
if (rpm_check(release:"CentOS-3", reference:"cups-libs-1.1.17-13.3.54")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"cups-1.1.22-0.rc1.9.27.el4_7.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"cups-1.1.22-0.rc1.9.27.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"cups-1.1.22-0.rc1.9.27.el4_7.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"cups-devel-1.1.22-0.rc1.9.27.el4_7.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"cups-devel-1.1.22-0.rc1.9.27.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"cups-devel-1.1.22-0.rc1.9.27.el4_7.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"cups-libs-1.1.22-0.rc1.9.27.el4_7.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"cups-libs-1.1.22-0.rc1.9.27.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"cups-libs-1.1.22-0.rc1.9.27.el4_7.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"cups-1.2.4-11.18.el5_2.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cups-devel-1.2.4-11.18.el5_2.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cups-libs-1.2.4-11.18.el5_2.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cups-lpd-1.2.4-11.18.el5_2.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
