#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0498 and 
# CentOS Errata and Security Advisory 2008:0498 respectively.
#

include("compat.inc");

if (description)
{
  script_id(33109);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/05/19 23:34:18 $");

  script_cve_id("CVE-2008-1722");
  script_bugtraq_id(28781);
  script_osvdb_id(44398);
  script_xref(name:"RHSA", value:"2008:0498");

  script_name(english:"CentOS 3 / 4 / 5 : cups (CESA-2008:0498)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated cups packages that fix a security issue are now available for
Red Hat Enterprise Linux 3, Red Hat Enterprise Linux 4, and Red Hat
Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Common UNIX Printing System (CUPS) provides a portable printing
layer for UNIX operating systems.

An integer overflow flaw leading to a heap buffer overflow was
discovered in the Portable Network Graphics (PNG) decoding routines
used by the CUPS image converting filters 'imagetops' and
'imagetoraster'. An attacker could create a malicious PNG file that
could possibly execute arbitrary code as the 'lp' user if the file was
printed. (CVE-2008-1722)

All CUPS users are advised to upgrade to these updated packages, which
contain backported patch to resolve this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-June/014952.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9154d51e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-June/014953.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a48ec5a2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-June/014960.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3ce871bb"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-June/014961.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0e19774a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-June/014964.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cfe88dd8"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-June/014965.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?34369e45"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-June/015008.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e9ca9462"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-June/015009.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f7e5e692"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cups packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-lpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"cups-1.1.17-13.3.53")) flag++;
if (rpm_check(release:"CentOS-3", reference:"cups-devel-1.1.17-13.3.53")) flag++;
if (rpm_check(release:"CentOS-3", reference:"cups-libs-1.1.17-13.3.53")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"cups-1.1.22-0.rc1.9.20.2.el4_6.8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"cups-1.1.22-0.rc1.9.20.2.c4.8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"cups-1.1.22-0.rc1.9.20.2.el4_6.8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"cups-devel-1.1.22-0.rc1.9.20.2.el4_6.8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"cups-devel-1.1.22-0.rc1.9.20.2.c4.8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"cups-devel-1.1.22-0.rc1.9.20.2.el4_6.8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"cups-libs-1.1.22-0.rc1.9.20.2.el4_6.8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"cups-libs-1.1.22-0.rc1.9.20.2.c4.8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"cups-libs-1.1.22-0.rc1.9.20.2.el4_6.8")) flag++;

if (rpm_check(release:"CentOS-5", reference:"cups-1.2.4-11.18.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cups-devel-1.2.4-11.18.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cups-libs-1.2.4-11.18.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cups-lpd-1.2.4-11.18.el5_2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
