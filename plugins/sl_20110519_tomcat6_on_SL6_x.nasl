#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61051);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/16 19:47:26 $");

  script_cve_id("CVE-2010-3718", "CVE-2010-4172", "CVE-2011-0013");

  script_name(english:"Scientific Linux Security Update : tomcat6 on SL6.x i386/x86_64");
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

It was found that web applications could modify the location of the
Tomcat host's work directory. As web applications deployed on Tomcat
have read and write access to this directory, a malicious web
application could use this flaw to trick Tomcat into giving it read
and write access to an arbitrary directory on the file system.
(CVE-2010-3718)

A cross-site scripting (XSS) flaw was found in the Manager
application, used for managing web applications on Tomcat. If a remote
attacker could trick a user who is logged into the Manager application
into visiting a specially crafted URL, the attacker could perform
Manager application tasks with the privileges of the logged in user.
(CVE-2010-4172)

A second cross-site scripting (XSS) flaw was found in the Manager
application. A malicious web application could use this flaw to
conduct an XSS attack, leading to arbitrary web script execution with
the privileges of victims who are logged into and viewing Manager
application web pages. (CVE-2011-0013)

This update also fixes the following bugs :

  - A bug in the 'tomcat6' init script prevented additional
    Tomcat instances from starting. As well, running
    'service tomcat6 start' caused configuration options
    applied from '/etc/sysconfig/tomcat6' to be overwritten
    with those from '/etc/tomcat6/tomcat6.conf'. With this
    update, multiple instances of Tomcat run as expected.
    (BZ#636997)

  - The '/usr/share/java/' directory was missing a symbolic
    link to the '/usr/share/tomcat6/bin/tomcat-juli.jar'
    library. Because this library was mandatory for certain
    operations (such as running the Jasper JSP precompiler),
    the 'build-jar-repository' command was unable to compose
    a valid classpath. With this update, the missing
    symbolic link has been added. (BZ#661244)

  - Previously, the 'tomcat6' init script failed to start
    Tomcat with a 'This account is currently not available.'
    message when Tomcat was configured to run under a user
    that did not have a valid shell configured as a login
    shell. This update modifies the init script to work
    correctly regardless of the daemon user's login shell.
    Additionally, these new tomcat6 packages now set
    '/sbin/nologin' as the login shell for the 'tomcat' user
    upon installation, as recommended by deployment best
    practices. (BZ#678671)

  - Some standard Tomcat directories were missing write
    permissions for the 'tomcat' group, which could cause
    certain applications to fail with errors such as 'No
    output folder'. This update adds write permissions for
    the 'tomcat' group to the affected directories.
    (BZ#643809)

  - The '/usr/sbin/tomcat6' wrapper script used a hard-coded
    path to the 'catalina.out' file, which may have caused
    problems (such as for logging init script output) if
    Tomcat was being run with a user other than 'tomcat' and
    with CATALINA_BASE set to a directory other than the
    default. (BZ#695284, BZ#697504)

  - Stopping Tomcat could have resulted in traceback errors
    being logged to 'catalina.out' when certain web
    applications were deployed. (BZ#698624)

Users of Tomcat should upgrade to these updated packages, which
contain backported patches to correct these issues. Tomcat must be
restarted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1106&L=scientific-linux-errata&T=0&P=2006
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?72ffe080"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=636997"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=643809"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=661244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=678671"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=695284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=697504"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=698624"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/19");
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
if (rpm_check(release:"SL6", reference:"tomcat6-6.0.24-33.el6")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-admin-webapps-6.0.24-33.el6")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-docs-webapp-6.0.24-33.el6")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-el-2.1-api-6.0.24-33.el6")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-javadoc-6.0.24-33.el6")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-jsp-2.1-api-6.0.24-33.el6")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-lib-6.0.24-33.el6")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-servlet-2.5-api-6.0.24-33.el6")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-webapps-6.0.24-33.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
