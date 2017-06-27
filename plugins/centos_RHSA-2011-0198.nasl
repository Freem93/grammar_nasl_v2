#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0198 and 
# CentOS Errata and Security Advisory 2011:0198 respectively.
#

include("compat.inc");

if (description)
{
  script_id(53417);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/04/28 18:05:37 $");

  script_cve_id("CVE-2010-4015");
  script_bugtraq_id(46084);
  script_osvdb_id(70740);
  script_xref(name:"RHSA", value:"2011:0198");

  script_name(english:"CentOS 5 : postgresql84 (CESA-2011:0198)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated postgresql84 packages that fix one security issue are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

PostgreSQL is an advanced object-relational database management system
(DBMS).

A stack-based buffer overflow flaw was found in the way PostgreSQL
processed certain tokens from a SQL query when the intarray module was
enabled on a particular database. An authenticated database user
running a specially crafted SQL query could use this flaw to cause a
temporary denial of service (postgres daemon crash) or, potentially,
execute arbitrary code with the privileges of the database server.
(CVE-2010-4015)

Red Hat would like to thank Geoff Keating of the Apple Product
Security team for reporting this issue.

These updated postgresql84 packages upgrade PostgreSQL to version
8.4.7. Refer to the PostgreSQL Release Notes for a full list of
changes :

http://www.postgresql.org/docs/8.4/static/release.html

All PostgreSQL users are advised to upgrade to these updated packages,
which correct this issue. If the postgresql service is running, it
will be automatically restarted after installing this update."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017383.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e946154f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017384.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?47bdf5a7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql84 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql84");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql84-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql84-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql84-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql84-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql84-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql84-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql84-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql84-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql84-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql84-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql84-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/15");
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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"postgresql84-8.4.7-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql84-contrib-8.4.7-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql84-devel-8.4.7-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql84-docs-8.4.7-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql84-libs-8.4.7-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql84-plperl-8.4.7-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql84-plpython-8.4.7-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql84-pltcl-8.4.7-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql84-python-8.4.7-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql84-server-8.4.7-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql84-tcl-8.4.7-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql84-test-8.4.7-1.el5_6.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
