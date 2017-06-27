#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1590 and 
# CentOS Errata and Security Advisory 2012:1590 respectively.
#

include("compat.inc");

if (description)
{
  script_id(63306);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/04 14:39:52 $");

  script_cve_id("CVE-2012-3401", "CVE-2012-4447", "CVE-2012-4564", "CVE-2012-5581");
  script_bugtraq_id(54601, 55673, 56372, 56715);
  script_osvdb_id(84090, 86548, 86878, 88155);
  script_xref(name:"RHSA", value:"2012:1590");

  script_name(english:"CentOS 5 / 6 : libtiff (CESA-2012:1590)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libtiff packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The libtiff packages contain a library of functions for manipulating
Tagged Image File Format (TIFF) files.

A heap-based buffer overflow flaw was found in the way libtiff
processed certain TIFF images using the Pixar Log Format encoding. An
attacker could create a specially crafted TIFF file that, when opened,
could cause an application using libtiff to crash or, possibly,
execute arbitrary code with the privileges of the user running the
application. (CVE-2012-4447)

A stack-based buffer overflow flaw was found in the way libtiff
handled DOTRANGE tags. An attacker could use this flaw to create a
specially crafted TIFF file that, when opened, would cause an
application linked against libtiff to crash or, possibly, execute
arbitrary code. (CVE-2012-5581)

A heap-based buffer overflow flaw was found in the tiff2pdf tool. An
attacker could use this flaw to create a specially crafted TIFF file
that would cause tiff2pdf to crash or, possibly, execute arbitrary
code. (CVE-2012-3401)

A missing return value check flaw, leading to a heap-based buffer
overflow, was found in the ppm2tiff tool. An attacker could use this
flaw to create a specially crafted PPM (Portable Pixel Map) file that
would cause ppm2tiff to crash or, possibly, execute arbitrary code.
(CVE-2012-4564)

The CVE-2012-5581, CVE-2012-3401, and CVE-2012-4564 issues were
discovered by Huzaifa Sidhpurwala of the Red Hat Security Response
Team.

All libtiff users should upgrade to these updated packages, which
contain backported patches to resolve these issues. All running
applications linked against libtiff must be restarted for this update
to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-December/019037.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9ee7fde1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-December/019038.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?24a057b8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libtiff packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtiff-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtiff-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"libtiff-3.8.2-18.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libtiff-devel-3.8.2-18.el5_8")) flag++;

if (rpm_check(release:"CentOS-6", reference:"libtiff-3.9.4-9.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libtiff-devel-3.9.4-9.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libtiff-static-3.9.4-9.el6_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
