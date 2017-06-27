#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0180 and 
# CentOS Errata and Security Advisory 2008:0180 respectively.
#

include("compat.inc");

if (description)
{
  script_id(31627);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/17 20:59:09 $");

  script_cve_id("CVE-2007-5971", "CVE-2008-0062", "CVE-2008-0063");
  script_bugtraq_id(26750, 28303);
  script_osvdb_id(43341, 43342, 43345);
  script_xref(name:"RHSA", value:"2008:0180");

  script_name(english:"CentOS 4 : krb5 (CESA-2008:0180)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated krb5 packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 4.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Kerberos is a network authentication system which allows clients and
servers to authenticate to each other through use of symmetric
encryption and a trusted third party, the KDC.

A flaw was found in the way the MIT Kerberos Authentication Service
and Key Distribution Center server (krb5kdc) handled Kerberos v4
protocol packets. An unauthenticated remote attacker could use this
flaw to crash the krb5kdc daemon, disclose portions of its memory, or
possibly execute arbitrary code using malformed or truncated Kerberos
v4 protocol requests. (CVE-2008-0062, CVE-2008-0063)

This issue only affected krb5kdc with Kerberos v4 protocol
compatibility enabled, which is the default setting on Red Hat
Enterprise Linux 4. Kerberos v4 protocol support can be disabled by
adding 'v4_mode=none' (without the quotes) to the '[kdcdefaults]'
section of /var/kerberos/krb5kdc/kdc.conf.

Red Hat would like to thank MIT for reporting these issues.

A double-free flaw was discovered in the GSSAPI library used by MIT
Kerberos. This flaw could possibly cause a crash of the application
using the GSSAPI library. (CVE-2007-5971)

All krb5 users are advised to update to these erratum packages which
contain backported fixes to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-March/014768.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2e9d4d66"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-March/014769.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c189bb54"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-March/014774.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?abb95a55"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected krb5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"krb5-devel-1.3.4-54.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"krb5-devel-1.3.4-54.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"krb5-devel-1.3.4-54.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"krb5-libs-1.3.4-54.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"krb5-libs-1.3.4-54.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"krb5-libs-1.3.4-54.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"krb5-server-1.3.4-54.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"krb5-server-1.3.4-54.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"krb5-server-1.3.4-54.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"krb5-workstation-1.3.4-54.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"krb5-workstation-1.3.4-54.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"krb5-workstation-1.3.4-54.el4_6.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
