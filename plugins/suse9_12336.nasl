#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(41268);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/21 20:33:29 $");

  script_cve_id("CVE-2008-2086", "CVE-2008-5339", "CVE-2008-5340", "CVE-2008-5341", "CVE-2008-5342", "CVE-2008-5343", "CVE-2008-5344", "CVE-2008-5345", "CVE-2008-5346", "CVE-2008-5348", "CVE-2008-5350", "CVE-2008-5351", "CVE-2008-5352", "CVE-2008-5353", "CVE-2008-5354", "CVE-2008-5356", "CVE-2008-5357", "CVE-2008-5359", "CVE-2008-5360");

  script_name(english:"SuSE9 Security Update : IBM Java5 JRE and SDK (YOU Patch Number 12336)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 9 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update brings IBM Java 5 to Service Release 9.

It fixes the following security problems :

  - A security vulnerability in the Java Runtime Environment
    (JRE) may allow an untrusted applet or application to
    list the contents of the home directory of the user
    running the applet or application. (CVE-2008-5350)

  - A security vulnerability in the Java Runtime Environment
    (JRE) with parsing zip files may allow an untrusted
    applet or application to read arbitrary memory locations
    in the process that the applet or application is running
    in. (CVE-2008-5346)

  - A vulnerability in Java Web Start and Java Plug-in may
    allow hidden code on a host to make network connections
    to that host and to hijack HTTP sessions using cookies
    stored in the browser. (CVE-2008-5343)

  - A vulnerability in the Java Runtime Environment (JRE)
    with applet classloading may allow an untrusted applet
    to read arbitrary files on a system that the applet runs
    on and make network connections to hosts other than the
    host it was loaded from. (CVE-2008-5344)

  - A buffer overflow vulnerability in the Java Runtime
    Environment (JRE) image processing code may allow an
    untrusted applet or application to escalate privileges.
    For example, an untrusted applet may grant itself
    permissions to read and write local files or execute
    local applications that are accessible to the user
    running the untrusted applet. (CVE-2008-5359)

  - A vulnerability in the Java Runtime Environment may
    allow an untrusted Java Web Start application to
    determine the location of the Java Web Start cache and
    the username of the user running the Java Web Start
    application. (CVE-2008-5341)

  - A vulnerability in the Java Runtime Environment (JRE)
    may allow an untrusted Java Web Start application to
    make network connections to hosts other than the host
    that the application is downloaded from. (CVE-2008-5339)

  - A vulnerability in the Java Runtime Environment with
    launching Java Web Start applications may allow an
    untrusted Java Web Start application to escalate
    privileges. For example, an untrusted application may
    grant itself permissions to read and write local files
    or execute local applications that are accessible to the
    user running the untrusted application. (CVE-2008-5340)

  - A security vulnerability in the Java Runtime Environment
    (JRE) with authenticating users through Kerberos may
    lead to a Denial of Service (DoS) to the system as a
    whole, due to excessive consumption of operating system
    resources. (CVE-2008-5348)

  - A vulnerability in Java Web Start may allow certain
    trusted operations to be performed, such as modifying
    system properties. (CVE-2008-2086)

  - The Java Runtime Environment (JRE) allows code loaded
    from the local filesystem to access localhost. This may
    allow code that is maliciously placed on the local
    filesystem and then subsequently run, to have network
    access to localhost that would not otherwise be allowed
    if the code were loaded from a remote host. This may be
    leveraged to steal cookies and hijack sessions (for
    domains that map a name to the localhost).
    (CVE-2008-5345)

  - The UTF-8 (Unicode Transformation Format-8) decoder in
    the Java Runtime Environment (JRE) accepts encodings
    that are longer than the 'shortest' form. This behavior
    is not a vulnerability in Java SE. However, it may be
    leveraged to exploit systems running software that
    relies on the JRE UTF-8 decoder to reject non-shortest
    form sequences. For example, non-shortest form sequences
    may be decoded into illegal URIs, which may then allow
    files that are not otherwise accessible to be read, if
    the URIs are not checked following UTF-8 decoding.
    (CVE-2008-5351)

  - The Java Runtime Environment creates temporary files
    with insufficiently random names. This may be leveraged
    to write JAR files which may then be loaded as untrusted
    applets and Java Web Start applications to access and
    provide services from localhost and hence steal cookies.
    (CVE-2008-5360)

  - A security vulnerability in the Java Runtime Environment
    (JRE) related to deserializing calendar objects may
    allow an untrusted applet or application to escalate
    privileges. For example, an untrusted applet may grant
    itself permissions to read and write local files or
    execute local applications that are accessible to the
    user running the untrusted applet. (CVE-2008-5353)

  - A buffer vulnerability in the Java Runtime Environment
    (JRE) with processing fonts may allow an untrusted
    applet or Java Web Start application to escalate
    privileges. For example, an untrusted applet may grant
    itself permissions to read and write local files or
    execute local applications that are accessible to the
    user running the untrusted applet. (CVE-2008-5356)

  - A buffer overflow vulnerability in the Java Runtime
    Environment (JRE) may allow an untrusted Java
    application that is launched through the command line to
    escalate privileges. For example, the untrusted Java
    application may grant itself permissions to read and
    write local files or execute local applications that are
    accessible to the user running the untrusted Java
    application. (CVE-2008-5354)

This vulnerability cannot be exploited by an applet or Java Web Start
application.

  - A buffer vulnerability in the Java Runtime Environment
    (JRE) with processing fonts may allow an untrusted
    applet or Java Web Start application to escalate
    privileges. For example, an untrusted applet may grant
    itself permissions to read and write local files or
    execute local applications that are accessible to the
    user running the untrusted applet. (CVE-2008-5357)

  - A buffer overflow vulnerability in the Java Runtime
    Environment (JRE) with unpacking applets and Java Web
    Start applications using the 'unpack200' JAR unpacking
    utility may allow an untrusted applet or application to
    escalate privileges. For example, an untrusted applet
    may grant itself permissions to read and write local
    files or execute local applications that are accessible
    to the user running the untrusted applet.
    (CVE-2008-5352)

  - A security vulnerability in the the Java Web Start
    BasicService allows untrusted applications that are
    downloaded from another system to request local files to
    be displayed by the browser of the user running the
    untrusted application. (CVE-2008-5342)

References can be found on :

http://www-128.ibm.com/developerworks/java/jdk/alerts/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-2086.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5339.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5340.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5341.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5342.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5343.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5344.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5345.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5346.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5348.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5350.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5351.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5352.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5353.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5354.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5356.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5357.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5359.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5360.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply YOU patch number 12336.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java Calendar Deserialization Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94, 119, 189, 200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 9 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"IBMJava5-JRE-1.5.0-0.57")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"IBMJava5-SDK-1.5.0-0.57")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"IBMJava5-JRE-1.5.0-0.56")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"IBMJava5-SDK-1.5.0-0.56")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
