#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:2021 and 
# CentOS Errata and Security Advisory 2014:2021 respectively.
#

include("compat.inc");

if (description)
{
  script_id(80107);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/01/30 15:10:02 $");

  script_cve_id("CVE-2014-8137", "CVE-2014-8138", "CVE-2014-9029");
  script_bugtraq_id(71476);
  script_osvdb_id(77595, 115355, 115481, 115482, 116027, 116028);
  script_xref(name:"RHSA", value:"2014:2021");

  script_name(english:"CentOS 6 / 7 : jasper (CESA-2014:2021)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated jasper packages that fix three security issues are now
available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

JasPer is an implementation of Part 1 of the JPEG 2000 image
compression standard.

Multiple off-by-one flaws, leading to heap-based buffer overflows,
were found in the way JasPer decoded JPEG 2000 image files. A
specially crafted file could cause an application using JasPer to
crash or, possibly, execute arbitrary code. (CVE-2014-9029)

A heap-based buffer overflow flaw was found in the way JasPer decoded
JPEG 2000 image files. A specially crafted file could cause an
application using JasPer to crash or, possibly, execute arbitrary
code. (CVE-2014-8138)

A double free flaw was found in the way JasPer parsed ICC color
profiles in JPEG 2000 image files. A specially crafted file could
cause an application using JasPer to crash or, possibly, execute
arbitrary code. (CVE-2014-8137)

Red Hat would like to thank oCERT for reporting these issues. oCERT
acknowledges Jose Duart of the Google Security Team as the original
reporter.

All JasPer users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. All
applications using the JasPer libraries must be restarted for the
update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-December/020847.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?09db416c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-December/020848.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4e08c17e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected jasper packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:jasper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:jasper-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:jasper-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:jasper-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"jasper-1.900.1-16.el6_6.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"jasper-devel-1.900.1-16.el6_6.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"jasper-libs-1.900.1-16.el6_6.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"jasper-utils-1.900.1-16.el6_6.2")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"jasper-1.900.1-26.el7_0.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"jasper-devel-1.900.1-26.el7_0.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"jasper-libs-1.900.1-26.el7_0.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"jasper-utils-1.900.1-26.el7_0.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
