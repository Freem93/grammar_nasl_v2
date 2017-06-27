#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:1095 and 
# CentOS Errata and Security Advisory 2007:1095 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43662);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/05/19 23:34:18 $");

  script_cve_id("CVE-2007-6110");
  script_bugtraq_id(26610);
  script_osvdb_id(13520, 40229);
  script_xref(name:"RHSA", value:"2007:1095");

  script_name(english:"CentOS 4 / 5 : htdig (CESA-2007:1095)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated htdig packages that resolve a security issue are now available
for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The ht://Dig system is a complete World Wide Web indexing and
searching system for a small domain or intranet.

A cross-site scripting flaw was discovered in a htdig search page. An
attacker could construct a carefully crafted URL, which once visited
by an unsuspecting user, could cause a user's Web browser to execute
malicious script in the context of the visited htdig search Web page.
(CVE-2007-6110)

Users of htdig are advised to upgrade to these updated packages, which
contain backported patch to resolve this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-December/014477.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e1ecc65b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-December/014481.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ba9bc886"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-December/014482.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5adf9769"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected htdig packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:htdig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:htdig-web");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"htdig-3.2.0b6-4.c4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"htdig-web-3.2.0b6-4.c4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"htdig-3.2.0b6-9.0.1.el5_1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"htdig-web-3.2.0b6-9.0.1.el5_1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
