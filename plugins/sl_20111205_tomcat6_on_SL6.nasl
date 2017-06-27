#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61184);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/16 19:47:27 $");

  script_cve_id("CVE-2011-1184", "CVE-2011-2204", "CVE-2011-2526", "CVE-2011-3190");

  script_name(english:"Scientific Linux Security Update : tomcat6 on SL6.x");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Apache Tomcat is a servlet container for the Java Servlet and
JavaServer Pages (JSP) technologies.

APR (Apache Portable Runtime) as mentioned in the CVE-2011-3190 and
CVE-2011-2526 descriptions does not refer to APR provided by the apr
packages. It refers to the implementation of APR provided by the
Tomcat Native library, which provides support for using APR with
Tomcat. This library is not shipped with Scientific Linux 6. This
update includes fixes for users who have elected to use APR with
Tomcat by taking the Tomcat Native library from a different product.

Multiple flaws were found in the way Tomcat handled HTTP DIGEST
authentication. These flaws weakened the Tomcat HTTP DIGEST
authentication implementation, subjecting it to some of the weaknesses
of HTTP BASIC authentication, for example, allowing remote attackers
to perform session replay attacks. (CVE-2011-1184)

A flaw was found in the way the Coyote
(org.apache.coyote.ajp.AjpProcessor) and APR
(org.apache.coyote.ajp.AjpAprProcessor) Tomcat AJP (Apache JServ
Protocol) connectors processed certain POST requests. An attacker
could send a specially crafted request that would cause the connector
to treat the message body as a new request. This allows arbitrary AJP
messages to be injected, possibly allowing an attacker to bypass a web
application's authentication checks and gain access to information
they would otherwise be unable to access. The JK
(org.apache.jk.server.JkCoyoteHandler) connector is used by default
when the APR libraries are not present. The JK connector is not
affected by this flaw. (CVE-2011-3190)

A flaw was found in the Tomcat MemoryUserDatabase. If a runtime
exception occurred when creating a new user with a JMX client, that
user's password was logged to Tomcat log files. Note: By default, only
administrators have access to such log files. (CVE-2011-2204)

A flaw was found in the way Tomcat handled sendfile request attributes
when using the HTTP APR or NIO (Non-Blocking I/O) connector. A
malicious web application running on a Tomcat instance could use this
flaw to bypass security manager restrictions and gain access to files
it would otherwise be unable to access, or possibly terminate the Java
Virtual Machine (JVM). The HTTP blocking IO (BIO) connector, which is
not vulnerable to this issue, is used by default in Scientific Linux
6. (CVE-2011-2526)

This update also fixes the following bug :

  - Previously, in certain cases, if 'LANG=fr_FR' or
    'LANG=fr_FR.UTF-8' was set as an environment variable or
    in '/etc/sysconfig/tomcat6' on 64-bit PowerPC systems,
    Tomcat may have failed to start correctly. With this
    update, Tomcat works as expected when LANG is set to
    'fr_FR' or 'fr_FR.UTF-8'.

Users of Tomcat should upgrade to these updated packages, which
contain backported patches to correct these issues. Tomcat must be
restarted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1112&L=scientific-linux-errata&T=0&P=482
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?46576f86"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"tomcat6-6.0.24-35.el6_1")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-admin-webapps-6.0.24-35.el6_1")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-docs-webapp-6.0.24-35.el6_1")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-el-2.1-api-6.0.24-35.el6_1")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-javadoc-6.0.24-35.el6_1")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-jsp-2.1-api-6.0.24-35.el6_1")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-lib-6.0.24-35.el6_1")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-servlet-2.5-api-6.0.24-35.el6_1")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-webapps-6.0.24-35.el6_1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
