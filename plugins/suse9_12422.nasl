#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(41302);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/21 20:33:29 $");

  script_cve_id("CVE-2009-1093", "CVE-2009-1094", "CVE-2009-1095", "CVE-2009-1096", "CVE-2009-1098", "CVE-2009-1099", "CVE-2009-1100", "CVE-2009-1103", "CVE-2009-1104", "CVE-2009-1107");

  script_name(english:"SuSE9 Security Update : IBM Java 5 JRE and IBM Java 5 SDK (YOU Patch Number 12422)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 9 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The update brings IBM Java 5 to SR9-SSU.

It fixes a lot of security issues :

  - A vulnerability in the Java Runtime Environment (JRE)
    with storing temporary font files may allow an untrusted
    applet or application to consume a disproportionate
    amount of disk space resulting in a denial-of-service
    condition. (CVE-2009-1100)

  - A vulnerability in the Java Runtime Environment (JRE)
    with processing temporary font files may allow an
    untrusted applet or application to retain temporary
    files resulting in a denial-of-service condition.
    (CVE-2009-1100)

  - A vulnerability in the Java Plug-in with deserializing
    applets may allow an untrusted applet to escalate
    privileges. For example, an untrusted applet may grant
    itself permissions to read and write local files or
    execute local applications that are accessible to the
    user running the untrusted applet. (CVE-2009-1103)

  - The Java Plug-in allows JavaScript code that is loaded
    from the localhost to connect to any port on the system.
    This may be leveraged together with XSS vulnerabilities
    in a blended attack to access other applications
    listening on ports other than the one where the
    JavaScript code was served from. (CVE-2009-1104)

  - A vulnerability in the Java Runtime Environment (JRE)
    with initializing LDAP connections may be exploited by a
    remote client to cause a denial-of-service condition on
    the LDAP service. (CVE-2009-1093)

  - A vulnerability in Java Runtime Environment LDAP client
    implementation may allow malicious data from an LDAP
    server to cause malicious code to be unexpectedly loaded
    and executed on an LDAP client. (CVE-2009-1094)

  - The Java Plugin displays a warning dialog for signed
    applets. A signed applet can obscure the contents of the
    dialog and trick a user into trusting the applet.
    (CVE-2009-1107)

  - Buffer overflow vulnerabilities in the Java Runtime
    Environment (JRE) with unpacking applets and Java Web
    Start applications using the unpack200 JAR unpacking
    utility may allow an untrusted applet or application to
    escalate privileges. For example, an untrusted applet
    may grant itself permissions to read and write local
    files or execute local applications that are accessible
    to the user running the untrusted applet. (CVE-2009-1095
    / CVE-2009-1096)

  - A buffer overflow vulnerability in the Java Runtime
    Environment with processing GIF images may allow an
    untrusted applet or Java Web Start application to
    escalate privileges. For example, an untrusted applet
    may grant itself permissions to read and write local
    files or execute local applications that are accessible
    to the user running the untrusted applet.
    (CVE-2009-1098)

  - A buffer overflow vulnerability in the Java Runtime
    Environment with processing fonts may allow an untrusted
    applet or Java Web Start application to escalate
    privileges. For example, an untrusted applet may grant
    itself permissions to read and write local files or
    execute local applications that are accessible to the
    user running the untrusted applet. (CVE-2009-1099)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1093.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1094.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1095.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1096.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1098.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1099.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1100.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1103.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1104.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1107.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply YOU patch number 12422.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(16, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/15");
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
if (rpm_check(release:"SUSE9", reference:"IBMJava5-JRE-1.5.0-0.64")) flag++;
if (rpm_check(release:"SUSE9", reference:"IBMJava5-SDK-1.5.0-0.64")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
