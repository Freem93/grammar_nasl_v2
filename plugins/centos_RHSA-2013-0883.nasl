#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0883 and 
# CentOS Errata and Security Advisory 2013:0883 respectively.
#

include("compat.inc");

if (description)
{
  script_id(66701);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/10/16 10:40:37 $");

  script_cve_id("CVE-2013-2116");
  script_bugtraq_id(60215);
  script_xref(name:"RHSA", value:"2013:0883");

  script_name(english:"CentOS 5 / 6 : gnutls (CESA-2013:0883)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gnutls packages that fix one security issue are now available
for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The GnuTLS library provides support for cryptographic algorithms and
for protocols such as Transport Layer Security (TLS).

It was discovered that the fix for the CVE-2013-1619 issue released
via RHSA-2013:0588 introduced a regression in the way GnuTLS decrypted
TLS/SSL encrypted records when CBC-mode cipher suites were used. A
remote attacker could possibly use this flaw to crash a server or
client application that uses GnuTLS. (CVE-2013-2116)

Users of GnuTLS are advised to upgrade to these updated packages,
which correct this issue. For the update to take effect, all
applications linked to the GnuTLS library must be restarted."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2013-May/019766.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2013-May/019767.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnutls packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls-guile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/31");
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
if (rpm_check(release:"CentOS-5", reference:"gnutls-1.4.1-10.el5_9.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"gnutls-devel-1.4.1-10.el5_9.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"gnutls-utils-1.4.1-10.el5_9.2")) flag++;

if (rpm_check(release:"CentOS-6", reference:"gnutls-2.8.5-10.el6_4.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gnutls-devel-2.8.5-10.el6_4.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gnutls-guile-2.8.5-10.el6_4.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gnutls-utils-2.8.5-10.el6_4.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
