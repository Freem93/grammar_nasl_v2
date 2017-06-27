#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0427 and 
# CentOS Errata and Security Advisory 2010:0427 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(46695);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/04/28 18:05:37 $");

  script_cve_id("CVE-2009-4136", "CVE-2010-0442", "CVE-2010-0733", "CVE-2010-1169", "CVE-2010-1170");
  script_osvdb_id(64755, 64756, 64757);
  script_xref(name:"RHSA", value:"2010:0427");

  script_name(english:"CentOS 3 : postgresql (CESA-2010:0427)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated postgresql packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 3.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

PostgreSQL is an advanced object-relational database management system
(DBMS). PL/Perl and PL/Tcl allow users to write PostgreSQL functions
in the Perl and Tcl languages, and are installed in trusted mode by
default. In trusted mode, certain operations, such as operating system
level access, are restricted.

A flaw was found in the way PostgreSQL enforced permission checks on
scripts written in PL/Perl. If the PL/Perl procedural language was
registered on a particular database, an authenticated database user
running a specially crafted PL/Perl script could use this flaw to
bypass intended PL/Perl trusted mode restrictions, allowing them to
run arbitrary Perl scripts with the privileges of the database server.
(CVE-2010-1169)

Red Hat would like to thank Tim Bunce for responsibly reporting the
CVE-2010-1169 flaw.

A flaw was found in the way PostgreSQL enforced permission checks on
scripts written in PL/Tcl. If the PL/Tcl procedural language was
registered on a particular database, an authenticated database user
running a specially crafted PL/Tcl script could use this flaw to
bypass intended PL/Tcl trusted mode restrictions, allowing them to run
arbitrary Tcl scripts with the privileges of the database server.
(CVE-2010-1170)

A buffer overflow flaw was found in the way PostgreSQL retrieved a
substring from the bit string for BIT() and BIT VARYING() SQL data
types. An authenticated database user running a specially crafted SQL
query could use this flaw to cause a temporary denial of service
(postgres daemon crash) or, potentially, execute arbitrary code with
the privileges of the database server. (CVE-2010-0442)

An integer overflow flaw was found in the way PostgreSQL used to
calculate the size of the hash table for joined relations. An
authenticated database user could create a specially crafted SQL query
which could cause a temporary denial of service (postgres daemon
crash) or, potentially, execute arbitrary code with the privileges of
the database server. (CVE-2010-0733)

PostgreSQL improperly protected session-local state during the
execution of an index function by a database superuser during the
database maintenance operations. An authenticated database user could
use this flaw to elevate their privileges via specially crafted index
functions. (CVE-2009-4136)

All PostgreSQL users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. Running
PostgreSQL instances must be restarted ('service rhdb restart') for
this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2010-May/016640.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2010-May/016642.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/24");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"rh-postgresql-7.3.21-3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"rh-postgresql-7.3.21-3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"rh-postgresql-contrib-7.3.21-3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"rh-postgresql-contrib-7.3.21-3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"rh-postgresql-devel-7.3.21-3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"rh-postgresql-devel-7.3.21-3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"rh-postgresql-docs-7.3.21-3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"rh-postgresql-docs-7.3.21-3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"rh-postgresql-jdbc-7.3.21-3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"rh-postgresql-jdbc-7.3.21-3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"rh-postgresql-libs-7.3.21-3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"rh-postgresql-libs-7.3.21-3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"rh-postgresql-pl-7.3.21-3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"rh-postgresql-pl-7.3.21-3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"rh-postgresql-python-7.3.21-3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"rh-postgresql-python-7.3.21-3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"rh-postgresql-server-7.3.21-3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"rh-postgresql-server-7.3.21-3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"rh-postgresql-tcl-7.3.21-3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"rh-postgresql-tcl-7.3.21-3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"rh-postgresql-test-7.3.21-3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"rh-postgresql-test-7.3.21-3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
