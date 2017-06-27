#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1549 and 
# CentOS Errata and Security Advisory 2009:1549 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67069);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/04 14:30:42 $");

  script_cve_id("CVE-2009-3490");
  script_bugtraq_id(36205);
  script_osvdb_id(57632);
  script_xref(name:"RHSA", value:"2009:1549");

  script_name(english:"CentOS 3 / 4 / 5 : wget (CESA-2009:1549)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated wget package that fixes a security issue is now available
for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

GNU Wget is a file retrieval utility that can use HTTP, HTTPS, and
FTP.

Daniel Stenberg reported that Wget is affected by the previously
published 'null prefix attack', caused by incorrect handling of NULL
characters in X.509 certificates. If an attacker is able to get a
carefully-crafted certificate signed by a trusted Certificate
Authority, the attacker could use the certificate during a
man-in-the-middle attack and potentially confuse Wget into accepting
it by mistake. (CVE-2009-3490)

Wget users should upgrade to this updated package, which contains a
backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-November/016298.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e29f1890"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-November/016299.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?df6878fd"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-November/016306.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dc21982c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-November/016307.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0079fa92"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-November/016324.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?76f09d91"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-November/016325.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e02a0c56"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected wget package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wget");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"wget-1.10.2-0.30E.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"wget-1.10.2-0.30E.1")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"wget-1.10.2-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"wget-1.10.2-1.el4_8.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"wget-1.11.4-2.el5_4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
