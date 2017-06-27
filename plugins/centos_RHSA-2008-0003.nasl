#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0003 and 
# CentOS Errata and Security Advisory 2008:0003 respectively.
#

include("compat.inc");

if (description)
{
  script_id(29901);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/04 14:30:41 $");

  script_cve_id("CVE-2007-5497");
  script_bugtraq_id(26772);
  script_osvdb_id(40161);
  script_xref(name:"RHSA", value:"2008:0003");

  script_name(english:"CentOS 3 / 4 / 5 : e2fsprogs (CESA-2008:0003)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated e2fsprogs packages that fix several security issues are now
available for Red Hat Enterprise Linux.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The e2fsprogs packages contain a number of utilities for creating,
checking, modifying, and correcting any inconsistencies in second and
third extended (ext2/ext3) file systems.

Multiple integer overflow flaws were found in the way e2fsprogs
processes file system content. If a victim opens a carefully crafted
file system with a program using e2fsprogs, it may be possible to
execute arbitrary code with the permissions of the victim. It may be
possible to leverage this flaw in a virtualized environment to gain
access to other virtualized hosts. (CVE-2007-5497)

Red Hat would like to thank Rafal Wojtczuk of McAfee Avert Research
for responsibly disclosing these issues.

Users of e2fsprogs are advised to upgrade to these updated packages,
which contain a backported patch to resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-January/014559.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2afdda79"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-January/014561.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca329549"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-January/014565.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f675f896"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-January/014566.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9faf7ba3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-January/014587.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a64dd325"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-January/014588.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b0dbbb7e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-January/014597.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?51cf9f62"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-January/014598.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9d1db912"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected e2fsprogs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:e2fsprogs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:e2fsprogs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:e2fsprogs-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/10");
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
if (rpm_check(release:"CentOS-3", reference:"e2fsprogs-1.32-15.4")) flag++;
if (rpm_check(release:"CentOS-3", reference:"e2fsprogs-devel-1.32-15.4")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"e2fsprogs-1.35-12.11.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"e2fsprogs-1.35-12.11.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"e2fsprogs-1.35-12.11.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"e2fsprogs-devel-1.35-12.11.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"e2fsprogs-devel-1.35-12.11.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"e2fsprogs-devel-1.35-12.11.el4_6.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"e2fsprogs-1.39-10.el5_1.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"e2fsprogs-devel-1.39-10.el5_1.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"e2fsprogs-libs-1.39-10.el5_1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
