#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0720 and 
# CentOS Errata and Security Advisory 2010:0720 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(49714);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/17 21:12:10 $");

  script_cve_id("CVE-2007-6720", "CVE-2009-3995", "CVE-2009-3996", "CVE-2009-3997", "CVE-2010-2546", "CVE-2010-2971");
  script_bugtraq_id(33235, 37374);
  script_xref(name:"RHSA", value:"2010:0720");

  script_name(english:"CentOS 3 / 4 / 5 : mikmod (CESA-2010:0720)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mikmod packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 3, 4, and 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

MikMod is a MOD music file player for Linux, UNIX, and similar
operating systems. It supports various file formats including MOD,
STM, S3M, MTM, XM, ULT, and IT.

Multiple input validation flaws, resulting in buffer overflows, were
discovered in MikMod. Specially crafted music files in various formats
could, when played, cause an application using the MikMod library to
crash or, potentially, execute arbitrary code. (CVE-2009-3995,
CVE-2009-3996, CVE-2007-6720)

All MikMod users should upgrade to these updated packages, which
contain backported patches to correct these issues. All running
applications using the MikMod library must be restarted for this
update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-October/017063.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2ef74f63"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-October/017064.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3db3b380"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-September/017024.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?67c08cda"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-September/017025.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?054c6b3d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-September/017026.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a4995971"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-September/017027.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4c4072bc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mikmod packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mikmod");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mikmod-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"mikmod-3.1.6-23.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"mikmod-3.1.6-23.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"mikmod-devel-3.1.6-23.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"mikmod-devel-3.1.6-23.el3")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"mikmod-3.1.6-33.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"mikmod-3.1.6-33.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"mikmod-devel-3.1.6-33.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"mikmod-devel-3.1.6-33.el4_8.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"mikmod-3.1.6-39.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mikmod-devel-3.1.6-39.el5_5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
