#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0583 and 
# CentOS Errata and Security Advisory 2008:0583 respectively.
#

include("compat.inc");

if (description)
{
  script_id(33490);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/05/19 23:34:19 $");

  script_cve_id("CVE-2008-2952");
  script_bugtraq_id(30013);
  script_xref(name:"RHSA", value:"2008:0583");

  script_name(english:"CentOS 4 / 5 : openldap (CESA-2008:0583)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openldap packages that fix a security issue are now available
for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

OpenLDAP is an open source suite of Lightweight Directory Access
Protocol (LDAP) applications and development tools. LDAP is a set of
protocols for accessing directory services.

A denial of service flaw was found in the way the OpenLDAP slapd
daemon processed certain network messages. An unauthenticated remote
attacker could send a specially crafted request that would crash the
slapd daemon. (CVE-2008-2952)

Users of openldap should upgrade to these updated packages, which
contain a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-July/015094.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5d38a389"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-July/015100.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b967801b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-July/015101.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cec0878e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-July/015108.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eca021bd"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-July/015109.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?98468051"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openldap packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:compat-openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-servers-sql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"compat-openldap-2.1.30-8.el4_6.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"compat-openldap-2.1.30-8.c4.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"compat-openldap-2.1.30-8.el4_6.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openldap-2.2.13-8.el4_6.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openldap-2.2.13-8.c4.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openldap-2.2.13-8.el4_6.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openldap-clients-2.2.13-8.el4_6.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openldap-clients-2.2.13-8.c4.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openldap-clients-2.2.13-8.el4_6.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openldap-devel-2.2.13-8.el4_6.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openldap-devel-2.2.13-8.c4.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openldap-devel-2.2.13-8.el4_6.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openldap-servers-2.2.13-8.el4_6.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openldap-servers-2.2.13-8.c4.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openldap-servers-2.2.13-8.el4_6.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openldap-servers-sql-2.2.13-8.el4_6.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openldap-servers-sql-2.2.13-8.c4.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openldap-servers-sql-2.2.13-8.el4_6.5")) flag++;

if (rpm_check(release:"CentOS-5", reference:"compat-openldap-2.3.27_2.2.29-8.el5_2.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openldap-2.3.27-8.el5_2.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openldap-clients-2.3.27-8.el5_2.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openldap-devel-2.3.27-8.el5_2.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openldap-servers-2.3.27-8.el5_2.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openldap-servers-sql-2.3.27-8.el5_2.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
