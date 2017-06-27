#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0839 and 
# CentOS Errata and Security Advisory 2008:0839 respectively.
#

include("compat.inc");

if (description)
{
  script_id(33890);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/04 14:30:41 $");

  script_cve_id("CVE-2008-2936");
  script_bugtraq_id(30691);
  script_osvdb_id(47658);
  script_xref(name:"RHSA", value:"2008:0839");

  script_name(english:"CentOS 3 / 4 / 5 : postfix (CESA-2008:0839)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated postfix packages that fix a security issue are now available
for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Postfix is a Mail Transport Agent (MTA), supporting LDAP, SMTP AUTH
(SASL), and TLS.

A flaw was found in the way Postfix dereferences symbolic links. If a
local user has write access to a mail spool directory with no root
mailbox, it may be possible for them to append arbitrary data to files
that root has write permission to. (CVE-2008-2936)

Red Hat would like to thank Sebastian Krahmer for responsibly
disclosing this issue.

All users of postfix should upgrade to these updated packages, which
contain a backported patch that resolves this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-August/015185.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?694ce034"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-August/015186.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?15f7d4d0"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-August/015187.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f67cc64a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-August/015188.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?99f95ab1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-August/015197.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fc8e1f45"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-August/015199.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?57bc31e2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postfix packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postfix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postfix-pflogsumm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/15");
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
if (rpm_check(release:"CentOS-3", reference:"postfix-2.0.16-14.1.RHEL3")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"postfix-2.2.10-1.2.1.c4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"postfix-pflogsumm-2.2.10-1.2.1.c4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"postfix-2.3.3-2.1.el5_2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postfix-pflogsumm-2.3.3-2.1.el5_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
