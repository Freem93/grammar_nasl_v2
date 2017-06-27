#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60440);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2008-1185", "CVE-2008-1186", "CVE-2008-1187", "CVE-2008-1188", "CVE-2008-1189", "CVE-2008-1190", "CVE-2008-1191", "CVE-2008-1192", "CVE-2008-1193", "CVE-2008-1194", "CVE-2008-1195", "CVE-2008-1196", "CVE-2008-3103", "CVE-2008-3104", "CVE-2008-3107", "CVE-2008-3111", "CVE-2008-3112", "CVE-2008-3113", "CVE-2008-3114");

  script_name(english:"Scientific Linux Security Update : java (jdk 1.5.0) on SL4.x, SL5.x i386/x86_64");
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
"Flaws in the JRE allowed an untrusted application or applet to elevate
its privileges. This could be exploited by a remote attacker to access
local files or execute local applications accessible to the user
running the JRE (CVE-2008-1185, CVE-2008-1186)

A flaw was found in the Java XSLT processing classes. An untrusted
application or applet could cause a denial of service, or execute
arbitrary code with the permissions of the user running the JRE.
(CVE-2008-1187)

Several buffer overflow flaws were found in Java Web Start (JWS). An
untrusted JNLP application could access local files or execute local
applications accessible to the user running the JRE. (CVE-2008-1188,
CVE-2008-1189, CVE-2008-1190, CVE-2008-1191, CVE-2008-1196)

A flaw was found in the Java Plug-in. A remote attacker could bypass
the same origin policy, executing arbitrary code with the permissions
of the user running the JRE. (CVE-2008-1192)

A flaw was found in the JRE image parsing libraries. An untrusted
application or applet could cause a denial of service, or possible
execute arbitrary code with the permissions of the user running the
JRE. (CVE-2008-1193)

A flaw was found in the JRE color management library. An untrusted
application or applet could trigger a denial of service (JVM crash).
(CVE-2008-1194)

The JRE allowed untrusted JavaScript code to create local network
connections by the use of Java APIs. A remote attacker could use these
flaws to access local network services. (CVE-2008-1195)

A vulnerability was found in the Java Management Extensions (JMX)
management agent, when local monitoring is enabled. This allowed
remote attackers to perform illegal operations. (CVE-2008-3103)

Multiple vulnerabilities with unsigned applets were reported. A remote
attacker could misuse an unsigned applet to connect to localhost
services running on the host running the applet. (CVE-2008-3104)

A Java Runtime Environment (JRE) vulnerability could be triggered by
an untrusted application or applet. A remote attacker could grant an
untrusted applet extended privileges such as reading and writing local
files, or executing local programs. (CVE-2008-3107)

Several buffer overflow vulnerabilities in Java Web Start were
reported. These vulnerabilities may allow an untrusted Java Web Start
application to elevate its privileges and thereby grant itself
permission to read and/or write local files, as well as to execute
local applications accessible to the user running the untrusted
application. (CVE-2008-3111)

Two file processing vulnerabilities in Java Web Start were found. A
remote attacker, by means of an untrusted Java Web Start application,
was able to create or delete arbitrary files with the permissions of
the user running the untrusted application. (CVE-2008-3112,
CVE-2008-3113)

A vulnerability in Java Web Start when processing untrusted
applications was reported. An attacker was able to acquire sensitive
information, such as the cache location. (CVE-2008-3114)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0807&L=scientific-linux-errata&T=0&P=3334
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f7b26f48"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.5.0-sun-compat and / or jdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(20, 119, 200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL4", reference:"java-1.5.0-sun-compat-1.5.0.16-1.1.sl.jpp")) flag++;
if (rpm_check(release:"SL4", reference:"jdk-1.5.0_16-fcs")) flag++;

if (rpm_check(release:"SL5", reference:"java-1.5.0-sun-compat-1.5.0.16-1.1.sl5.jpp")) flag++;
if (rpm_check(release:"SL5", reference:"jdk-1.5.0_16-fcs")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
