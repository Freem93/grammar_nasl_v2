#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1264 and 
# CentOS Errata and Security Advisory 2012:1264 respectively.
#

include("compat.inc");

if (description)
{
  script_id(62084);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/04 14:39:51 $");

  script_cve_id("CVE-2012-3488");
  script_bugtraq_id(55072);
  script_osvdb_id(84805);
  script_xref(name:"RHSA", value:"2012:1264");

  script_name(english:"CentOS 5 : postgresql (CESA-2012:1264)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated postgresql packages that fix one security issue are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

PostgreSQL is an advanced object-relational database management system
(DBMS).

It was found that the optional PostgreSQL xml2 contrib module allowed
local files and remote URLs to be read and written to with the
privileges of the database server when parsing Extensible Stylesheet
Language Transformations (XSLT). An unprivileged database user could
use this flaw to read and write to local files (such as the database's
configuration files) and remote URLs they would otherwise not have
access to by issuing a specially crafted SQL query. (CVE-2012-3488)

Red Hat would like to thank the PostgreSQL project for reporting this
issue. Upstream acknowledges Peter Eisentraut as the original
reporter.

All PostgreSQL users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. If the
postgresql service is running, it will be automatically restarted
after installing this update."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-September/018869.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7433cf3c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"postgresql-8.1.23-6.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-contrib-8.1.23-6.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-devel-8.1.23-6.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-docs-8.1.23-6.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-libs-8.1.23-6.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-pl-8.1.23-6.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-python-8.1.23-6.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-server-8.1.23-6.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-tcl-8.1.23-6.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-test-8.1.23-6.el5_8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
