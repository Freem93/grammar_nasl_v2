#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0874 and 
# CentOS Errata and Security Advisory 2012:0874 respectively.
#

include("compat.inc");

if (description)
{
  script_id(59926);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/10/17 10:45:15 $");

  script_cve_id("CVE-2012-2102");
  script_bugtraq_id(52931);
  script_osvdb_id(81059);
  script_xref(name:"RHSA", value:"2012:0874");

  script_name(english:"CentOS 6 : mysql (CESA-2012:0874)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mysql packages that fix one security issue and add one
enhancement are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

MySQL is a multi-user, multi-threaded SQL database server. It consists
of the MySQL server daemon (mysqld) and many client programs and
libraries.

A flaw was found in the way MySQL processed HANDLER READ NEXT
statements after deleting a record. A remote, authenticated attacker
could use this flaw to provide such requests, causing mysqld to crash.
This issue only caused a temporary denial of service, as mysqld was
automatically restarted after the crash. (CVE-2012-2102)

This update also adds the following enhancement :

* The InnoDB storage engine is built-in for all architectures. This
update adds InnoDB Plugin, the InnoDB storage engine as a plug-in for
the 32-bit x86, AMD64, and Intel 64 architectures. The plug-in offers
additional features and better performance than when using the
built-in InnoDB storage engine. Refer to the MySQL documentation,
linked to in the References section, for information about enabling
the plug-in. (BZ#740224)

All MySQL users should upgrade to these updated packages, which add
this enhancement and contain a backported patch to correct this issue.
After installing this update, the MySQL server daemon (mysqld) will be
restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-July/018716.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?acd96cae"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"mysql-5.1.61-4.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mysql-bench-5.1.61-4.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mysql-devel-5.1.61-4.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mysql-embedded-5.1.61-4.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mysql-embedded-devel-5.1.61-4.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mysql-libs-5.1.61-4.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mysql-server-5.1.61-4.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mysql-test-5.1.61-4.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
