#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2004:611. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15631);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/05/02 17:31:16 $");

  script_cve_id("CVE-2004-0835", "CVE-2004-0836", "CVE-2004-0837", "CVE-2004-0957");
  script_osvdb_id(10658, 10659, 10660, 10959);
  script_xref(name:"RHSA", value:"2004:611");

  script_name(english:"RHEL 3 : mysql-server (RHSA-2004:611)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated mysql-server package that fixes various security issues is
now available in the Red Hat Enterprise Linux 3 Extras channel of Red
Hat Network.

MySQL is a multi-user, multi-threaded SQL database server.

A number of security issues that affect the mysql-server package have
been reported. Although Red Hat Enterprise Linux 3 does not ship with
the mysql-server package, the affected package is available from the
Red Hat Network Extras channel.

Oleksandr Byelkin discovered that 'ALTER TABLE ... RENAME' checked the
CREATE/INSERT rights of the old table instead of the new one. The
Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2004-0835 to this issue.

Lukasz Wojtow discovered a buffer overrun in the mysql_real_connect
function. In order to exploit this issue an attacker would need to
force the use of a malicious DNS server (CVE-2004-0836).

Dean Ellis discovered that multiple threads ALTERing the same (or
different) MERGE tables to change the UNION could cause the server to
crash or stall (CVE-2004-0837).

Sergei Golubchik discovered that if a user is granted privileges to a
database with a name containing an underscore ('_'), the user also
gains the ability to grant privileges to other databases with similar
names (CVE-2004-0957).

Users of mysql-server should upgrade to these erratum packages, which
correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0835.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0836.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0837.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0957.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2004-611.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql-server package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/04");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/05/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

flag = 0;
if (rpm_check(release:"RHEL3", reference:"mysql-server-3.23.58-2.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
