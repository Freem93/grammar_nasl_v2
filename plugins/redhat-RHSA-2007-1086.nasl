#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:1086. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63846);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/01/10 18:05:23 $");

  script_cve_id("CVE-2007-2788", "CVE-2007-2789", "CVE-2007-3698", "CVE-2007-4381");
  script_xref(name:"RHSA", value:"2007:1086");

  script_name(english:"RHEL 4 : java-1.4.2-bea (RHSA-2007:1086)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.4.2-bea packages that correct several security issues
and add enhancements are now available for Red Hat Enterprise Linux 4
Extras.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The BEA WebLogic JRockit 1.4.2_15 JRE and SDK contain BEA WebLogic
JRockit Virtual Machine 1.4.2_15 and are certified for the Java 2
Platform, Standard Edition, v1.4.2.

A buffer overflow in the Java Runtime Environment image handling code
was found. If an attacker is able to cause a server application to
process a specially crafted image file, it may be possible to execute
arbitrary code as the user running the Java Virtual Machine.
(CVE-2007-2788, CVE-2007-2789, CVE-2007-3004)

A denial of service flaw was discovered in the Java Applet Viewer. An
untrusted Java applet could cause the Java Virtual Machine to become
unresponsive. Please note that the BEA WebLogic JRockit 1.4.2_15 does
not ship with a browser plug-in and therefore this issue could only be
triggered by a user running the 'appletviewer' application.
(CVE-2007-3005)

A denial of service flaw was found in the way the JSSE component
processed SSL/TLS handshake requests. A remote attacker able to
connect to a JSSE enabled service could send a specially crafted
handshake which would cause the Java Runtime Environment to stop
responding to future requests. (CVE-2007-3698)

A flaw was found in the way the Java Runtime Environment processes
font data. An applet viewed via the 'appletviewer' application could
elevate its privileges, allowing the applet to perform actions with
the same permissions as the user running the 'appletviewer'
application. It may also be possible to crash a server application
which processes untrusted font information from a third party.
(CVE-2007-4381)

All users of java-1.4.2-bea should upgrade to these updated packages,
which contain the BEA WebLogic JRockit 1.4.2_15 release that resolves
these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-2788.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-2789.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-3698.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-4381.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev2dev.bea.com/pub/advisory/249"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev2dev.bea.com/pub/advisory/248"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2007-1086.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected java-1.4.2-bea, java-1.4.2-bea-devel and / or
java-1.4.2-bea-jdbc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.4.2-bea");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.4.2-bea-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.4.2-bea-jdbc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.6");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"RHEL4", cpu:"i686", reference:"java-1.4.2-bea-1.4.2.15-1jpp.2.el4")) flag++;
if (rpm_check(release:"RHEL4", cpu:"i686", reference:"java-1.4.2-bea-devel-1.4.2.15-1jpp.2.el4")) flag++;
if (rpm_check(release:"RHEL4", cpu:"i686", reference:"java-1.4.2-bea-jdbc-1.4.2.15-1jpp.2.el4")) flag++;

if (rpm_check(release:"RHEL4", sp:"6", cpu:"i686", reference:"java-1.4.2-bea-1.4.2.15-1jpp.2.el4")) flag++;
if (rpm_check(release:"RHEL4", sp:"6", cpu:"i686", reference:"java-1.4.2-bea-devel-1.4.2.15-1jpp.2.el4")) flag++;
if (rpm_check(release:"RHEL4", sp:"6", cpu:"i686", reference:"java-1.4.2-bea-jdbc-1.4.2.15-1jpp.2.el4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
