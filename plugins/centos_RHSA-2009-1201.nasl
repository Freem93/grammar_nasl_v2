#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1201 and 
# CentOS Errata and Security Advisory 2009:1201 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(43774);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/17 20:59:10 $");

  script_cve_id("CVE-2009-0217", "CVE-2009-2475", "CVE-2009-2476", "CVE-2009-2625", "CVE-2009-2670", "CVE-2009-2671", "CVE-2009-2672", "CVE-2009-2673", "CVE-2009-2674", "CVE-2009-2675", "CVE-2009-2689", "CVE-2009-2690", "CVE-2009-3403");
  script_bugtraq_id(35671, 35922, 35939, 35942, 35943, 35944, 35958);
  script_osvdb_id(56965, 56966, 56967, 56968, 56984);
  script_xref(name:"RHSA", value:"2009:1201");

  script_name(english:"CentOS 5 : java-1.6.0-openjdk (CESA-2009:1201)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.6.0-openjdk packages that fix several security issues
and a bug are now available for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

These packages provide the OpenJDK 6 Java Runtime Environment and the
OpenJDK 6 Software Development Kit. The Java Runtime Environment (JRE)
contains the software and tools that users need to run applications
written using the Java programming language.

A flaw was found in the way the XML Digital Signature implementation
in the JRE handled HMAC-based XML signatures. An attacker could use
this flaw to create a crafted signature that could allow them to
bypass authentication, or trick a user, applet, or application into
accepting untrusted content. (CVE-2009-0217)

Several potential information leaks were found in various mutable
static variables. These could be exploited in application scenarios
that execute untrusted scripting code. (CVE-2009-2475)

It was discovered that OpenType checks can be bypassed. This could
allow a rogue application to bypass access restrictions by acquiring
references to privileged objects through finalizer resurrection.
(CVE-2009-2476)

A denial of service flaw was found in the way the JRE processes XML. A
remote attacker could use this flaw to supply crafted XML that would
lead to a denial of service. (CVE-2009-2625)

A flaw was found in the JRE audio system. An untrusted applet or
application could use this flaw to gain read access to restricted
System properties. (CVE-2009-2670)

Two flaws were found in the JRE proxy implementation. An untrusted
applet or application could use these flaws to discover the usernames
of users running applets and applications, or obtain web browser
cookies and use them for session hijacking attacks. (CVE-2009-2671,
CVE-2009-2672)

An additional flaw was found in the proxy mechanism implementation.
This flaw allowed an untrusted applet or application to bypass access
restrictions and communicate using non-authorized socket or URL
connections to hosts other than the origin host. (CVE-2009-2673)

An integer overflow flaw was found in the way the JRE processes JPEG
images. An untrusted application could use this flaw to extend its
privileges, allowing it to read and write local files, as well as to
execute local applications with the privileges of the user running the
application. (CVE-2009-2674)

An integer overflow flaw was found in the JRE unpack200 functionality.
An untrusted applet or application could extend its privileges,
allowing it to read and write local files, as well as to execute local
applications with the privileges of the user running the applet or
application. (CVE-2009-2675)

It was discovered that JDK13Services grants unnecessary privileges to
certain object types. This could be misused by an untrusted applet or
application to use otherwise restricted functionality. (CVE-2009-2689)

An information disclosure flaw was found in the way private Java
variables were handled. An untrusted applet or application could use
this flaw to obtain information from variables that would otherwise be
private. (CVE-2009-2690)

Note: The flaws concerning applets in this advisory, CVE-2009-2475,
CVE-2009-2670, CVE-2009-2671, CVE-2009-2672, CVE-2009-2673,
CVE-2009-2675, CVE-2009-2689, and CVE-2009-2690, can only be triggered
in java-1.6.0-openjdk by calling the 'appletviewer' application.

This update also fixes the following bug :

* the EVR in the java-1.6.0-openjdk package as shipped with Red Hat
Enterprise Linux allowed the java-1.6.0-openjdk package from the EPEL
repository to take precedence (appear newer). Users using
java-1.6.0-openjdk from EPEL would not have received security updates
since October 2008. This update prevents the packages from EPEL from
taking precedence. (BZ#499079)

All users of java-1.6.0-openjdk are advised to upgrade to these
updated packages, which resolve these issues. All running instances of
OpenJDK Java must be restarted for the update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-August/016064.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?35664ea7"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-August/016065.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dd329275"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.6.0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/09");
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
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-1.6.0.0-1.2.b09.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-demo-1.6.0.0-1.2.b09.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-devel-1.6.0.0-1.2.b09.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-1.2.b09.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-src-1.6.0.0-1.2.b09.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
