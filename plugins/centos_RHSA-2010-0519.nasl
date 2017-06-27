#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0519 and 
# CentOS Errata and Security Advisory 2010:0519 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(47738);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/05/19 23:43:07 $");

  script_cve_id("CVE-2010-1411", "CVE-2010-2481", "CVE-2010-2483", "CVE-2010-2595", "CVE-2010-2597", "CVE-2010-4665");
  script_bugtraq_id(40823, 41088, 41295);
  script_xref(name:"RHSA", value:"2010:0519");

  script_name(english:"CentOS 4 / 5 : libtiff (CESA-2010:0519)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libtiff packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 4 and 5.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The libtiff packages contain a library of functions for manipulating
Tagged Image File Format (TIFF) files.

Multiple integer overflow flaws, leading to a buffer overflow, were
discovered in libtiff. An attacker could use these flaws to create a
specially crafted TIFF file that, when opened, would cause an
application linked against libtiff to crash or, possibly, execute
arbitrary code. (CVE-2010-1411)

Multiple input validation flaws were discovered in libtiff. An
attacker could use these flaws to create a specially crafted TIFF file
that, when opened, would cause an application linked against libtiff
to crash. (CVE-2010-2481, CVE-2010-2483, CVE-2010-2595, CVE-2010-2597)

Red Hat would like to thank Apple Product Security for responsibly
reporting the CVE-2010-1411 flaw, who credit Kevin Finisterre of
digitalmunition.com for the discovery of the issue.

All libtiff users are advised to upgrade to these updated packages,
which contain backported patches to resolve these issues. All running
applications linked against libtiff must be restarted for this update
to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-July/016765.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5fe99779"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-July/016766.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?161c51d9"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-July/016807.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d6a25945"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-July/016808.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?270f9dc8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libtiff packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtiff-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libtiff-3.6.1-12.el4_8.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libtiff-3.6.1-12.el4_8.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libtiff-devel-3.6.1-12.el4_8.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libtiff-devel-3.6.1-12.el4_8.5")) flag++;

if (rpm_check(release:"CentOS-5", reference:"libtiff-3.8.2-7.el5_5.5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libtiff-devel-3.8.2-7.el5_5.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
