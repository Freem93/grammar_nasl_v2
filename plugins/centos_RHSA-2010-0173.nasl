#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0173 and 
# CentOS Errata and Security Advisory 2010:0173 respectively.
#

include("compat.inc");

if (description)
{
  script_id(45347);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/04 14:30:42 $");

  script_cve_id("CVE-2009-3245");
  script_bugtraq_id(38562);
  script_xref(name:"RHSA", value:"2010:0173");

  script_name(english:"CentOS 3 / 4 : openssl096b (CESA-2010:0173)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openssl096b packages that fix one security issue are now
available for Red Hat Enterprise Linux 3 and 4.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL
v2/v3) and Transport Layer Security (TLS v1) protocols, as well as a
full-strength, general purpose cryptography library.

It was discovered that OpenSSL did not always check the return value
of the bn_wexpand() function. An attacker able to trigger a memory
allocation failure in that function could cause an application using
the OpenSSL library to crash or, possibly, execute arbitrary code.
(CVE-2009-3245)

All openssl096b users should upgrade to these updated packages, which
contain a backported patch to resolve this issue. For the update to
take effect, all programs using the openssl096b library must be
restarted."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-March/016582.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bcf086d0"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-March/016583.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2eb85d90"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-March/016611.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f1028aa6"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-March/016612.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7d991b41"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl096b package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl096b");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/26");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"openssl096b-0.9.6b-16.50")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"openssl096b-0.9.6b-16.50")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openssl096b-0.9.6b-22.46.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openssl096b-0.9.6b-22.46.el4_8.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
