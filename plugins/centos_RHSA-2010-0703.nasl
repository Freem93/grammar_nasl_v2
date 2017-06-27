#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0703 and 
# CentOS Errata and Security Advisory 2010:0703 respectively.
#

include("compat.inc");

if (description)
{
  script_id(49633);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/05/20 05:01:05 $");

  script_cve_id("CVE-2010-0405");
  script_bugtraq_id(43331);
  script_osvdb_id(68167);
  script_xref(name:"RHSA", value:"2010:0703");
  script_xref(name:"IAVB", value:"2010-B-0083");

  script_name(english:"CentOS 3 / 4 / 5 : bzip2 (CESA-2010:0703)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated bzip2 packages that fix one security issue are now available
for Red Hat Enterprise Linux 3, 4, and 5.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

bzip2 is a freely available, high-quality data compressor. It provides
both standalone compression and decompression utilities, as well as a
shared library for use with other programs.

An integer overflow flaw was discovered in the bzip2 decompression
routine. This issue could, when decompressing malformed archives,
cause bzip2, or an application linked against the libbz2 library, to
crash or, potentially, execute arbitrary code. (CVE-2010-0405)

Users of bzip2 should upgrade to these updated packages, which contain
a backported patch to resolve this issue. All running applications
using the libbz2 library must be restarted for the update to take
effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-September/017012.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0b9c8a09"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-September/017013.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?874f8dfa"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-September/017014.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?617f03eb"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-September/017015.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?296c1db1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-September/017016.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5dc90297"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-September/017017.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4f885828"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bzip2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bzip2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bzip2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bzip2-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/22");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"bzip2-1.0.2-14.EL3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"bzip2-1.0.2-14.EL3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"bzip2-devel-1.0.2-14.EL3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"bzip2-devel-1.0.2-14.EL3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"bzip2-libs-1.0.2-14.EL3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"bzip2-libs-1.0.2-14.EL3")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"bzip2-1.0.2-16.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"bzip2-1.0.2-16.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"bzip2-devel-1.0.2-16.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"bzip2-devel-1.0.2-16.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"bzip2-libs-1.0.2-16.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"bzip2-libs-1.0.2-16.el4_8")) flag++;

if (rpm_check(release:"CentOS-5", reference:"bzip2-1.0.3-6.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bzip2-devel-1.0.3-6.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bzip2-libs-1.0.3-6.el5_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
