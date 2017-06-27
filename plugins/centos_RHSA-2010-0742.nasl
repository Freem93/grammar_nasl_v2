#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0742 and 
# CentOS Errata and Security Advisory 2010:0742 respectively.
#

include("compat.inc");

if (description)
{
  script_id(49781);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/04/28 18:05:37 $");

  script_cve_id("CVE-2010-3433");
  script_bugtraq_id(43747);
  script_osvdb_id(68436);
  script_xref(name:"RHSA", value:"2010:0742");

  script_name(english:"CentOS 4 / 5 : postgresql / postgresql84 (CESA-2010:0742)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated postgresql and postgresql84 packages that fix one security
issue are now available for Red Hat Enterprise Linux 4 and 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

PostgreSQL is an advanced object-relational database management system
(DBMS). PL/Perl and PL/Tcl allow users to write PostgreSQL functions
in the Perl and Tcl languages. The PostgreSQL SECURITY DEFINER
parameter, which can be used when creating a new PostgreSQL function,
specifies that the function will be executed with the privileges of
the user that created it.

It was discovered that a user could utilize the features of the
PL/Perl and PL/Tcl languages to modify the behavior of a SECURITY
DEFINER function created by a different user. If the PL/Perl or PL/Tcl
language was used to implement a SECURITY DEFINER function, an
authenticated database user could use a PL/Perl or PL/Tcl script to
modify the behavior of that function during subsequent calls in the
same session. This would result in the modified or injected code also
being executed with the privileges of the user who created the
SECURITY DEFINER function, possibly leading to privilege escalation.
(CVE-2010-3433)

For Red Hat Enterprise Linux 4, the updated postgresql packages
upgrade PostgreSQL to version 7.4.30. Refer to the PostgreSQL Release
Notes for a list of changes :

http://www.postgresql.org/docs/7.4/static/release.html

For Red Hat Enterprise Linux 5, the updated postgresql packages
upgrade PostgreSQL to version 8.1.22, and the updated postgresql84
packages upgrade PostgreSQL to version 8.4.5. Refer to the PostgreSQL
Release Notes for a list of changes :

http://www.postgresql.org/docs/8.1/static/release.html
http://www.postgresql.org/docs/8.4/static/release.html

All PostgreSQL users are advised to upgrade to these updated packages,
which correct this issue. If the postgresql service is running, it
will be automatically restarted after installing this update."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-October/017041.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ee4aa2dd"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-October/017042.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?509d3028"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-October/017059.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f7b04303"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-October/017060.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?83f5ec51"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-October/017069.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bb238da9"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-October/017070.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?55bcd38c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql and / or postgresql84 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-test");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-7.4.30-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-7.4.30-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-contrib-7.4.30-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-contrib-7.4.30-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-devel-7.4.30-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-devel-7.4.30-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-docs-7.4.30-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-docs-7.4.30-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-jdbc-7.4.30-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-jdbc-7.4.30-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-libs-7.4.30-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-libs-7.4.30-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-pl-7.4.30-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-pl-7.4.30-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-python-7.4.30-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-python-7.4.30-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-server-7.4.30-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-server-7.4.30-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-tcl-7.4.30-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-tcl-7.4.30-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-test-7.4.30-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-test-7.4.30-1.el4_8.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"postgresql-8.1.22-1.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-contrib-8.1.22-1.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-devel-8.1.22-1.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-docs-8.1.22-1.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-libs-8.1.22-1.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-pl-8.1.22-1.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-python-8.1.22-1.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-server-8.1.22-1.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-tcl-8.1.22-1.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-test-8.1.22-1.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql84-8.4.5-1.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql84-contrib-8.4.5-1.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql84-devel-8.4.5-1.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql84-docs-8.4.5-1.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql84-libs-8.4.5-1.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql84-plperl-8.4.5-1.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql84-plpython-8.4.5-1.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql84-pltcl-8.4.5-1.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql84-python-8.4.5-1.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql84-server-8.4.5-1.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql84-tcl-8.4.5-1.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql84-test-8.4.5-1.el5_5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
