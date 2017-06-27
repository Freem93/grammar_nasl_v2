#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1840 and 
# CentOS Errata and Security Advisory 2015:1840 respectively.
#

include("compat.inc");

if (description)
{
  script_id(86515);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/04/28 18:05:39 $");

  script_cve_id("CVE-2015-6908");
  script_osvdb_id(127342);
  script_xref(name:"RHSA", value:"2015:1840");

  script_name(english:"CentOS 5 / 6 / 7 : openldap (CESA-2015:1840)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openldap packages that fix one security issue are now
available for Red Hat Enterprise Linux 5, 6, and 7.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

OpenLDAP is an open source suite of Lightweight Directory Access
Protocol (LDAP) applications and development tools. LDAP is a set of
protocols used to access and maintain distributed directory
information services over an IP network. The openldap package contains
configuration files, libraries, and documentation for OpenLDAP.

A flaw was found in the way the OpenLDAP server daemon (slapd) parsed
certain Basic Encoding Rules (BER) data. A remote attacker could use
this flaw to crash slapd via a specially crafted packet.
(CVE-2015-6908)

All openldap users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-September/021418.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?99ebaaa0"
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-September/021419.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f70119ad"
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-September/021420.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c05330ae"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openldap packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:compat-openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-servers-overlays");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-servers-sql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"compat-openldap-2.3.43_2.2.29-29.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openldap-2.3.43-29.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openldap-clients-2.3.43-29.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openldap-devel-2.3.43-29.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openldap-servers-2.3.43-29.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openldap-servers-overlays-2.3.43-29.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openldap-servers-sql-2.3.43-29.el5_11")) flag++;

if (rpm_check(release:"CentOS-6", reference:"openldap-2.4.40-6.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openldap-clients-2.4.40-6.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openldap-devel-2.4.40-6.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openldap-servers-2.4.40-6.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openldap-servers-sql-2.4.40-6.el6_7")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openldap-2.4.39-7.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openldap-clients-2.4.39-7.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openldap-devel-2.4.39-7.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openldap-servers-2.4.39-7.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openldap-servers-sql-2.4.39-7.el7.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
