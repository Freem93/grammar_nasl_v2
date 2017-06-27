#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0225 and 
# CentOS Errata and Security Advisory 2017:0225 respectively.
#

include("compat.inc");

if (description)
{
  script_id(96929);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/02/02 14:39:40 $");

  script_cve_id("CVE-2015-8870", "CVE-2016-5652", "CVE-2016-9533", "CVE-2016-9534", "CVE-2016-9535", "CVE-2016-9536", "CVE-2016-9537", "CVE-2016-9540");
  script_xref(name:"RHSA", value:"2017:0225");

  script_name(english:"CentOS 6 / 7 : libtiff (CESA-2017:0225)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for libtiff is now available for Red Hat Enterprise Linux 6
and Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The libtiff packages contain a library of functions for manipulating
Tagged Image File Format (TIFF) files.

Security Fix(es) :

* Multiple flaws have been discovered in libtiff. A remote attacker
could exploit these flaws to cause a crash or memory corruption and,
possibly, execute arbitrary code by tricking an application linked
against libtiff into processing specially crafted files.
(CVE-2016-9533, CVE-2016-9534, CVE-2016-9535)

* Multiple flaws have been discovered in various libtiff tools
(tiff2pdf, tiffcrop, tiffcp, bmp2tiff). By tricking a user into
processing a specially crafted file, a remote attacker could exploit
these flaws to cause a crash or memory corruption and, possibly,
execute arbitrary code with the privileges of the user running the
libtiff tool. (CVE-2015-8870, CVE-2016-5652, CVE-2016-9540,
CVE-2016-9537, CVE-2016-9536)"
  );
  # http://lists.centos.org/pipermail/centos-announce/2017-February/022259.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?83cc297b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2017-February/022261.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3d2e1948"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libtiff packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtiff-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtiff-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtiff-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/02");
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
if (rpm_check(release:"CentOS-6", reference:"libtiff-3.9.4-21.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libtiff-devel-3.9.4-21.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libtiff-static-3.9.4-21.el6_8")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libtiff-4.0.3-27.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libtiff-devel-4.0.3-27.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libtiff-static-4.0.3-27.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libtiff-tools-4.0.3-27.el7_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
