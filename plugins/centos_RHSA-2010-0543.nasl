#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0543 and 
# CentOS Errata and Security Advisory 2010:0543 respectively.
#

include("compat.inc");

if (description)
{
  script_id(47790);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/26 15:53:26 $");

  script_cve_id("CVE-2009-3767", "CVE-2010-0211");
  script_bugtraq_id(36844, 41770);
  script_osvdb_id(66470);
  script_xref(name:"RHSA", value:"2010:0543");

  script_name(english:"CentOS 4 : openldap (CESA-2010:0543)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openldap packages that fix two security issues are now
available for Red Hat Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

OpenLDAP is an open source suite of LDAP (Lightweight Directory Access
Protocol) applications and development tools.

An uninitialized pointer use flaw was discovered in the way the slapd
daemon handled modify relative distinguished name (modrdn) requests.
An authenticated user with privileges to perform modrdn operations
could use this flaw to crash the slapd daemon via specially crafted
modrdn requests. (CVE-2010-0211)

Red Hat would like to thank CERT-FI for responsibly reporting the
CVE-2010-0211 flaw, who credit Ilkka Mattila and Tuomas Salomaki for
the discovery of the issue.

A flaw was found in the way OpenLDAP handled NUL characters in the
CommonName field of X.509 certificates. An attacker able to get a
carefully-crafted certificate signed by a trusted Certificate
Authority could trick applications using OpenLDAP libraries into
accepting it by mistake, allowing the attacker to perform a
man-in-the-middle attack. (CVE-2009-3767)

Users of OpenLDAP should upgrade to these updated packages, which
contain backported patches to resolve these issues. After installing
this update, the OpenLDAP daemons will be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-July/016791.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?51044460"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-July/016792.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a06e0dd9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openldap packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:compat-openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-servers-sql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/22");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"compat-openldap-2.1.30-12.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"compat-openldap-2.1.30-12.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openldap-2.2.13-12.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openldap-2.2.13-12.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openldap-clients-2.2.13-12.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openldap-clients-2.2.13-12.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openldap-devel-2.2.13-12.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openldap-devel-2.2.13-12.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openldap-servers-2.2.13-12.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openldap-servers-2.2.13-12.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openldap-servers-sql-2.2.13-12.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openldap-servers-sql-2.2.13-12.el4_8.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
