#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:1100 and 
# CentOS Errata and Security Advisory 2017:1100 respectively.
#

include("compat.inc");

if (description)
{
  script_id(99536);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/05/22 13:36:33 $");

  script_cve_id("CVE-2017-5461");
  script_osvdb_id(155952);
  script_xref(name:"RHSA", value:"2017:1100");

  script_name(english:"CentOS 6 / 7 : nss / nss-util (CESA-2017:1100)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for nss and nss-util is now available for Red Hat Enterprise
Linux 6 and Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Critical. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications.

The nss-util packages provide utilities for use with the Network
Security Services (NSS) libraries.

The following packages have been upgraded to a newer upstream version:
nss (3.28.4), nss-util (3.28.4).

Security Fix(es) :

* An out-of-bounds write flaw was found in the way NSS performed
certain Base64-decoding operations. An attacker could use this flaw to
create a specially crafted certificate which, when parsed by NSS,
could cause it to crash or execute arbitrary code, using the
permissions of the user running an application compiled against the
NSS library. (CVE-2017-5461)

Red Hat would like to thank the Mozilla project for reporting this
issue. Upstream acknowledges Ronald Crane as the original reporter."
  );
  # http://lists.centos.org/pipermail/centos-announce/2017-April/022391.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?39a99316"
  );
  # http://lists.centos.org/pipermail/centos-announce/2017-April/022392.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3e2a70e9"
  );
  # http://lists.centos.org/pipermail/centos-announce/2017-April/022396.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?561083d5"
  );
  # http://lists.centos.org/pipermail/centos-announce/2017-April/022397.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a17c6f92"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nss and / or nss-util packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-util-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/21");
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
if (rpm_check(release:"CentOS-6", reference:"nss-3.28.4-1.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-devel-3.28.4-1.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-pkcs11-devel-3.28.4-1.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-sysinit-3.28.4-1.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-tools-3.28.4-1.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-util-3.28.4-1.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-util-devel-3.28.4-1.el6_9")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-3.28.4-1.0.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-devel-3.28.4-1.0.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-pkcs11-devel-3.28.4-1.0.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-sysinit-3.28.4-1.0.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-tools-3.28.4-1.0.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-util-3.28.4-1.0.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-util-devel-3.28.4-1.0.el7_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
