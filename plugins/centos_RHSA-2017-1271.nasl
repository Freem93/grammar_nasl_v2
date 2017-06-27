#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:1271 and 
# CentOS Errata and Security Advisory 2017:1271 respectively.
#

include("compat.inc");

if (description)
{
  script_id(100429);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/26 15:15:35 $");

  script_cve_id("CVE-2017-7494");
  script_xref(name:"RHSA", value:"2017:1271");

  script_name(english:"CentOS 6 : samba4 (CESA-2017:1271)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for samba4 is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Samba is an open source implementation of the Server Message Block
(SMB) or Common Internet File System (CIFS) protocol, which allows
PC-compatible machines to share files, printers, and other
information.

Security Fix(es) :

* A remote code execution flaw was found in Samba. A malicious
authenticated samba client, having write access to the samba share,
could use this flaw to execute arbitrary code as root. (CVE-2017-7494)

Red Hat would like to thank the Samba project for reporting this
issue. Upstream acknowledges steelo as the original reporter."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2017-May/022418.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba4 packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba is_known_pipename() Arbitrary Module Load');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-dc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/26");
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
if (rpm_check(release:"CentOS-6", reference:"samba4-4.2.10-10.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-client-4.2.10-10.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-common-4.2.10-10.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-dc-4.2.10-10.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-dc-libs-4.2.10-10.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-devel-4.2.10-10.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-libs-4.2.10-10.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-pidl-4.2.10-10.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-python-4.2.10-10.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-test-4.2.10-10.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-winbind-4.2.10-10.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-winbind-clients-4.2.10-10.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-winbind-krb5-locator-4.2.10-10.el6_9")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");


