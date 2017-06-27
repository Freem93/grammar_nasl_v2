#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0892 and 
# CentOS Errata and Security Advisory 2007:0892 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43652);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/17 20:59:08 $");

  script_cve_id("CVE-2007-3999", "CVE-2007-4743");
  script_bugtraq_id(25534);
  script_osvdb_id(37332);
  script_xref(name:"RHSA", value:"2007:0892");
  script_xref(name:"TRA", value:"TRA-2007-07");

  script_name(english:"CentOS 5 : krb5 (CESA-2007:0892)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated krb5 packages that correct a security flaw are now available
for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Kerberos is a network authentication system which allows clients and
servers to authenticate to each other through use of symmetric
encryption and a trusted third party, the KDC. kadmind is the KADM5
administration server.

The MIT Kerberos Team discovered a problem with the originally
published patch for svc_auth_gss.c (CVE-2007-3999). A remote
unauthenticated attacker who can access kadmind could trigger this
flaw and cause kadmind to crash. On Red Hat Enterprise Linux 5 it is
not possible to exploit this flaw to run arbitrary code as the
overflow is blocked by FORTIFY_SOURCE. (CVE-2007-4743)

This issue did not affect the versions of Kerberos distributed with
Red Hat Enterprise Linux 2.1, 3, or 4.

Users of krb5-server are advised to update to these erratum packages
which contain a corrected backported fix for this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014186.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e26ada87"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014187.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?db58c8db"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2007-07"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected krb5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/09/05");
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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"krb5-devel-1.5-29")) flag++;
if (rpm_check(release:"CentOS-5", reference:"krb5-libs-1.5-29")) flag++;
if (rpm_check(release:"CentOS-5", reference:"krb5-server-1.5-29")) flag++;
if (rpm_check(release:"CentOS-5", reference:"krb5-workstation-1.5-29")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
