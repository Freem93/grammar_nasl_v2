#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0790 and 
# CentOS Errata and Security Advisory 2014:0790 respectively.
#

include("compat.inc");

if (description)
{
  script_id(76218);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/26 11:29:48 $");

  script_cve_id("CVE-2014-3430");
  script_bugtraq_id(67306);
  script_xref(name:"RHSA", value:"2014:0790");

  script_name(english:"CentOS 6 : dovecot (CESA-2014:0790)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated dovecot packages that fix one security issue are now available
for Red Hat Enterprise Linux 6 and 7.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Dovecot is an IMAP server, written with security primarily in mind,
for Linux and other UNIX-like systems. It also contains a small POP3
server. It supports mail in both the maildir or mbox format. The SQL
drivers and authentication plug-ins are provided as subpackages.

It was discovered that Dovecot did not properly discard connections
trapped in the SSL/TLS handshake phase. A remote attacker could use
this flaw to cause a denial of service on an IMAP/POP3 server by
exhausting the pool of available connections and preventing further,
legitimate connections to the IMAP/POP3 server to be made.
(CVE-2014-3430)

All dovecot users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. After
installing the updated packages, the dovecot service will be restarted
automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-June/020388.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2477c7fa"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dovecot packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dovecot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dovecot-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dovecot-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dovecot-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dovecot-pigeonhole");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"dovecot-2.0.9-7.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"dovecot-devel-2.0.9-7.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"dovecot-mysql-2.0.9-7.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"dovecot-pgsql-2.0.9-7.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"dovecot-pigeonhole-2.0.9-7.el6_5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
