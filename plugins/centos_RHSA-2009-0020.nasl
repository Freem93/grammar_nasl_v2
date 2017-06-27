#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0020 and 
# CentOS Errata and Security Advisory 2009:0020 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(35589);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/17 20:59:09 $");

  script_cve_id("CVE-2008-5077", "CVE-2009-0021", "CVE-2009-0025", "CVE-2009-0046", "CVE-2009-0047", "CVE-2009-0048", "CVE-2009-0049", "CVE-2009-0124", "CVE-2009-0125", "CVE-2009-0127", "CVE-2009-0128", "CVE-2009-0130");
  script_bugtraq_id(33151);
  script_xref(name:"RHSA", value:"2009:0020");

  script_name(english:"CentOS 3 / 4 / 5 : bind (CESA-2009:0020)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Bind packages to correct a security issue are now available
for Red Hat Enterprise Linux 2.1, 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

BIND (Berkeley Internet Name Domain) is an implementation of the DNS
(Domain Name System) protocols.

A flaw was discovered in the way BIND checked the return value of the
OpenSSL DSA_do_verify function. On systems using DNSSEC, a malicious
zone could present a malformed DSA certificate and bypass proper
certificate validation, allowing spoofing attacks. (CVE-2009-0025)

For users of Red Hat Enterprise Linux 3 this update also addresses a
bug which can cause BIND to occasionally exit with an assertion
failure.

All BIND users are advised to upgrade to the updated package, which
contains a backported patch to resolve this issue. After installing
the update, BIND daemon will be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-February/015582.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ce5b3c64"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-February/015584.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b80f95ac"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-February/015586.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bd1a960e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-February/015587.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d4d73742"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-January/015538.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3aebf76a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-January/015539.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?07d8d3c6"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-January/015552.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2fdfd4cd"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-January/015553.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6f8f135b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-libbind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:caching-nameserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"bind-9.2.4-23.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"bind-chroot-9.2.4-23.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"bind-devel-9.2.4-23.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"bind-libs-9.2.4-23.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"bind-utils-9.2.4-23.el3")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"bind-9.2.4-30.el4_7.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"bind-9.2.4-30.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"bind-9.2.4-30.el4_7.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"bind-chroot-9.2.4-30.el4_7.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"bind-chroot-9.2.4-30.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"bind-chroot-9.2.4-30.el4_7.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"bind-devel-9.2.4-30.el4_7.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"bind-devel-9.2.4-30.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"bind-devel-9.2.4-30.el4_7.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"bind-libs-9.2.4-30.el4_7.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"bind-libs-9.2.4-30.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"bind-libs-9.2.4-30.el4_7.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"bind-utils-9.2.4-30.el4_7.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"bind-utils-9.2.4-30.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"bind-utils-9.2.4-30.el4_7.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"bind-9.3.4-6.0.3.P1.el5_2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-chroot-9.3.4-6.0.3.P1.el5_2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-devel-9.3.4-6.0.3.P1.el5_2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-libbind-devel-9.3.4-6.0.3.P1.el5_2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-libs-9.3.4-6.0.3.P1.el5_2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-sdb-9.3.4-6.0.3.P1.el5_2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-utils-9.3.4-6.0.3.P1.el5_2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"caching-nameserver-9.3.4-6.0.3.P1.el5_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
