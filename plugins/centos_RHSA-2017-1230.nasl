#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:1230 and 
# CentOS Errata and Security Advisory 2017:1230 respectively.
#

include("compat.inc");

if (description)
{
  script_id(100175);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/16 13:59:27 $");

  script_cve_id("CVE-2017-8291");
  script_osvdb_id(156431);
  script_xref(name:"RHSA", value:"2017:1230");

  script_name(english:"CentOS 6 / 7 : ghostscript (CESA-2017:1230)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for ghostscript is now available for Red Hat Enterprise
Linux 6 and Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The Ghostscript suite contains utilities for rendering PostScript and
PDF documents. Ghostscript translates PostScript code to common bitmap
formats so that the code can be displayed or printed.

Security Fix(es) :

* It was found that ghostscript did not properly validate the
parameters passed to the .rsdparams and .eqproc functions. During its
execution, a specially crafted PostScript document could execute code
in the context of the ghostscript process, bypassing the -dSAFER
protection. (CVE-2017-8291)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2017-May/022409.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2017-May/022410.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ghostscript packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ghostscript-cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ghostscript-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ghostscript-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ghostscript-gtk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"ghostscript-8.70-23.el6_9.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ghostscript-devel-8.70-23.el6_9.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ghostscript-doc-8.70-23.el6_9.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ghostscript-gtk-8.70-23.el6_9.2")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ghostscript-9.07-20.el7_3.5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ghostscript-cups-9.07-20.el7_3.5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ghostscript-devel-9.07-20.el7_3.5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ghostscript-doc-9.07-20.el7_3.5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ghostscript-gtk-9.07-20.el7_3.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
