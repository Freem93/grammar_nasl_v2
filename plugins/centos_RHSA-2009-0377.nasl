#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0377 and 
# CentOS Errata and Security Advisory 2009:0377 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(43736);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/17 20:59:09 $");

  script_cve_id("CVE-2006-2426", "CVE-2009-0581", "CVE-2009-0723", "CVE-2009-0733", "CVE-2009-0793", "CVE-2009-1093", "CVE-2009-1094", "CVE-2009-1095", "CVE-2009-1096", "CVE-2009-1097", "CVE-2009-1098", "CVE-2009-1101", "CVE-2009-1102");
  script_bugtraq_id(34185, 34240);
  script_osvdb_id(53166, 56307, 56308, 56310);
  script_xref(name:"RHSA", value:"2009:0377");

  script_name(english:"CentOS 5 : java-1.6.0-openjdk (CESA-2009:0377)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.6.0-openjdk packages that fix several security issues
are now available for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

These packages provide the OpenJDK 6 Java Runtime Environment and the
OpenJDK 6 Software Development Kit. The Java Runtime Environment (JRE)
contains the software and tools that users need to run applications
written using the Java programming language.

A flaw was found in the way that the Java Virtual Machine (JVM)
handled temporary font files. A malicious applet could use this flaw
to use large amounts of disk space, causing a denial of service.
(CVE-2006-2426)

A memory leak flaw was found in LittleCMS (embedded in OpenJDK). An
application using color profiles could use excessive amounts of
memory, and possibly crash after using all available memory, if used
to open specially crafted images. (CVE-2009-0581)

Multiple integer overflow flaws which could lead to heap-based buffer
overflows, as well as multiple insufficient input validation flaws,
were found in the way LittleCMS handled color profiles. An attacker
could use these flaws to create a specially crafted image file which
could cause a Java application to crash or, possibly, execute
arbitrary code when opened. (CVE-2009-0723, CVE-2009-0733)

A NULL pointer dereference flaw was found in LittleCMS. An application
using color profiles could crash while converting a specially crafted
image file. (CVE-2009-0793)

A flaw in the Java API for XML Web Services (JAX-WS) service endpoint
handling could allow a remote attacker to cause a denial of service on
the server application hosting the JAX-WS service endpoint.
(CVE-2009-1101)

A flaw in the way the Java Runtime Environment initialized LDAP
connections could allow a remote, authenticated user to cause a denial
of service on the LDAP service. (CVE-2009-1093)

A flaw in the Java Runtime Environment LDAP client could allow
malicious data from an LDAP server to cause arbitrary code to be
loaded and then run on an LDAP client. (CVE-2009-1094)

Several buffer overflow flaws were found in the Java Runtime
Environment unpack200 functionality. An untrusted applet could extend
its privileges, allowing it to read and write local files, as well as
to execute local applications with the privileges of the user running
the applet. (CVE-2009-1095, CVE-2009-1096)

A flaw in the Java Runtime Environment Virtual Machine code generation
functionality could allow untrusted applets to extend their
privileges. An untrusted applet could extend its privileges, allowing
it to read and write local files, as well as execute local
applications with the privileges of the user running the applet.
(CVE-2009-1102)

A buffer overflow flaw was found in the splash screen processing. A
remote attacker could extend privileges to read and write local files,
as well as to execute local applications with the privileges of the
user running the java process. (CVE-2009-1097)

A buffer overflow flaw was found in how GIF images were processed. A
remote attacker could extend privileges to read and write local files,
as well as execute local applications with the privileges of the user
running the java process. (CVE-2009-1098)

Note: The flaws concerning applets in this advisory, CVE-2009-1095,
CVE-2009-1096, and CVE-2009-1102, can only be triggered in
java-1.6.0-openjdk by calling the 'appletviewer' application.

All users of java-1.6.0-openjdk are advised to upgrade to these
updated packages, which resolve these issues. All running instances of
OpenJDK Java must be restarted for the update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-April/015734.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7eb76bf6"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-April/015735.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2dab09ae"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.6.0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16, 20, 94, 119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/08");
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
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-1.6.0.0-0.30.b09.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-demo-1.6.0.0-0.30.b09.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-devel-1.6.0.0-0.30.b09.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-0.30.b09.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-src-1.6.0.0-0.30.b09.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
