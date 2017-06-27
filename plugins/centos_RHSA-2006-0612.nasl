#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0612 and 
# CentOS Errata and Security Advisory 2006:0612 respectively.
#

include("compat.inc");

if (description)
{
  script_id(22197);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/05/19 23:25:26 $");

  script_cve_id("CVE-2006-3083");
  script_bugtraq_id(19427);
  script_osvdb_id(27869, 27870, 27871, 27872);
  script_xref(name:"RHSA", value:"2006:0612");

  script_name(english:"CentOS 4 : krb5 (CESA-2006:0612)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated krb5 packages are now available for Red Hat Enterprise Linux 4
to correct a privilege escalation security flaw.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Kerberos is a network authentication system which allows clients and
servers to authenticate to each other through use of symmetric
encryption and a trusted third party, the KDC.

A flaw was found where some bundled Kerberos-aware applications would
fail to check the result of the setuid() call. On Linux 2.6 kernels,
the setuid() call can fail if certain user limits are hit. A local
attacker could manipulate their environment in such a way to get the
applications to continue to run as root, potentially leading to an
escalation of privileges. (CVE-2006-3083).

Users are advised to update to these erratum packages which contain a
backported fix to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-August/013129.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e983da85"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-August/013133.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ef9352ac"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-August/013134.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8c1488cc"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected krb5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"krb5-devel-1.3.4-33")) flag++;
if (rpm_check(release:"CentOS-4", reference:"krb5-libs-1.3.4-33")) flag++;
if (rpm_check(release:"CentOS-4", reference:"krb5-server-1.3.4-33")) flag++;
if (rpm_check(release:"CentOS-4", reference:"krb5-workstation-1.3.4-33")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
