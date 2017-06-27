#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0942 and 
# CentOS Errata and Security Advisory 2013:0942 respectively.
#

include("compat.inc");

if (description)
{
  script_id(66888);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/12/17 11:41:45 $");

  script_cve_id("CVE-2002-2443");
  script_bugtraq_id(60008);
  script_osvdb_id(93240);
  script_xref(name:"RHSA", value:"2013:0942");

  script_name(english:"CentOS 5 / 6 : krb5 (CESA-2013:0942)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated krb5 packages that fix one security issue are now available
for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Kerberos is a network authentication system which allows clients and
servers to authenticate to each other using symmetric encryption and a
trusted third-party, the Key Distribution Center (KDC).

It was found that kadmind's kpasswd service did not perform any
validation on incoming network packets, causing it to reply to all
requests. A remote attacker could use this flaw to send spoofed
packets to a kpasswd service that appear to come from kadmind on a
different server, causing the services to keep replying packets to
each other, consuming network bandwidth and CPU. (CVE-2002-2443)

All krb5 users should upgrade to these updated packages, which contain
a backported patch to correct this issue. After installing the updated
packages, the krb5kdc and kadmind daemons will be restarted
automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-June/019785.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4b53cc91"
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-June/019786.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?79e7e664"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected krb5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-pkinit-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-server-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"krb5-devel-1.6.1-70.el5_9.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"krb5-libs-1.6.1-70.el5_9.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"krb5-server-1.6.1-70.el5_9.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"krb5-server-ldap-1.6.1-70.el5_9.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"krb5-workstation-1.6.1-70.el5_9.2")) flag++;

if (rpm_check(release:"CentOS-6", reference:"krb5-devel-1.10.3-10.el6_4.3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"krb5-libs-1.10.3-10.el6_4.3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"krb5-pkinit-openssl-1.10.3-10.el6_4.3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"krb5-server-1.10.3-10.el6_4.3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"krb5-server-ldap-1.10.3-10.el6_4.3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"krb5-workstation-1.10.3-10.el6_4.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
