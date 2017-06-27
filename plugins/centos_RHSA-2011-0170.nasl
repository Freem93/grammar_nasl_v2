#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0170 and 
# CentOS Errata and Security Advisory 2011:0170 respectively.
#

include("compat.inc");

if (description)
{
  script_id(51885);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/04 14:30:42 $");

  script_cve_id("CVE-2011-0002");
  script_bugtraq_id(45791);
  script_osvdb_id(70421);
  script_xref(name:"RHSA", value:"2011:0170");

  script_name(english:"CentOS 4 / 5 : libuser (CESA-2011:0170)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libuser packages that fix one security issue are now available
for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The libuser library implements a standardized interface for
manipulating and administering user and group accounts. Sample
applications that are modeled after applications from the shadow
password suite (shadow-utils) are included in these packages.

It was discovered that libuser did not set the password entry
correctly when creating LDAP (Lightweight Directory Access Protocol)
users. If an administrator did not assign a password to an LDAP based
user account, either at account creation with luseradd, or with
lpasswd after account creation, an attacker could use this flaw to log
into that account with a default password string that should have been
rejected. (CVE-2011-0002)

Note: LDAP administrators that have used libuser tools to add users
should check existing user accounts for plain text passwords, and
reset them as necessary.

Users of libuser should upgrade to these updated packages, which
contain a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017424.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eb023342"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017427.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?98ccffee"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-February/017247.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?76ca05e2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-February/017248.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f7e899f4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libuser packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libuser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libuser-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libuser-0.52.5-1.1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libuser-0.52.5-1.1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libuser-devel-0.52.5-1.1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libuser-devel-0.52.5-1.1.el4_8.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"libuser-0.54.7-2.1.el5_5.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libuser-devel-0.54.7-2.1.el5_5.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
