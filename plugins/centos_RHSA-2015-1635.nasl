#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1635 and 
# CentOS Errata and Security Advisory 2015:1635 respectively.
#

include("compat.inc");

if (description)
{
  script_id(85463);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/05/20 13:54:06 $");

  script_cve_id("CVE-2015-3414", "CVE-2015-3415", "CVE-2015-3416");
  script_osvdb_id(120909, 120943, 120944);
  script_xref(name:"RHSA", value:"2015:1635");

  script_name(english:"CentOS 7 : sqlite (CESA-2015:1635)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated sqlite package that fixes three security issues is now
available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

SQLite is a C library that implements a SQL database engine. A large
subset of SQL92 is supported. A complete database is stored in a
single disk file. The API is designed for convenience and ease of use.
Applications that link against SQLite can enjoy the power and
flexibility of a SQL database without the administrative hassles of
supporting a separate database server.

A flaw was found in the way SQLite handled dequoting of
collation-sequence names. A local attacker could submit a specially
crafted COLLATE statement that would crash the SQLite process, or have
other unspecified impacts. (CVE-2015-3414)

It was found that SQLite's sqlite3VdbeExec() function did not properly
implement comparison operators. A local attacker could submit a
specially crafted CHECK statement that would crash the SQLite process,
or have other unspecified impacts. (CVE-2015-3415)

It was found that SQLite's sqlite3VXPrintf() function did not properly
handle precision and width values during floating-point conversions. A
local attacker could submit a specially crafted SELECT statement that
would crash the SQLite process, or have other unspecified impacts.
(CVE-2015-3416)

All sqlite users are advised to upgrade to this updated package, which
contains backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-August/021337.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d1baf76a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected sqlite packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:lemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sqlite-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sqlite-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sqlite-tcl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"lemon-3.7.17-6.el7_1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"sqlite-3.7.17-6.el7_1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"sqlite-devel-3.7.17-6.el7_1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"sqlite-doc-3.7.17-6.el7_1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"sqlite-tcl-3.7.17-6.el7_1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
