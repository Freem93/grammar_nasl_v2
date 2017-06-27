#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0479 and 
# CentOS Errata and Security Advisory 2009:0479 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43747);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/17 20:59:10 $");

  script_cve_id("CVE-2009-0663", "CVE-2009-1341");
  script_bugtraq_id(34755, 34757);
  script_xref(name:"RHSA", value:"2009:0479");

  script_name(english:"CentOS 5 : perl-DBD-Pg (CESA-2009:0479)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated perl-DBD-Pg package that fixes two security issues is now
available for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Perl DBI is a database access Application Programming Interface (API)
for the Perl language. perl-DBD-Pg allows Perl applications to access
PostgreSQL database servers.

A heap-based buffer overflow flaw was discovered in the pg_getline
function implementation. If the pg_getline or getline functions read
large, untrusted records from a database, it could cause an
application using these functions to crash or, possibly, execute
arbitrary code. (CVE-2009-0663)

Note: After installing this update, pg_getline may return more data
than specified by its second argument, as this argument will be
ignored. This is consistent with current upstream behavior.
Previously, the length limit (the second argument) was not enforced,
allowing a buffer overflow.

A memory leak flaw was found in the function performing the de-quoting
of BYTEA type values acquired from a database. An attacker able to
cause an application using perl-DBD-Pg to perform a large number of
SQL queries returning BYTEA records, could cause the application to
use excessive amounts of memory or, possibly, crash. (CVE-2009-1341)

All users of perl-DBD-Pg are advised to upgrade to this updated
package, which contains backported patches to fix these issues.
Applications using perl-DBD-Pg must be restarted for the update to
take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2009-May/015877.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2009-May/015878.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected perl-dbd-pg package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-DBD-Pg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"perl-DBD-Pg-1.49-2.el5_3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
