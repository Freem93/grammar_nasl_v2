#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29470);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/22 20:32:46 $");

  script_cve_id("CVE-2007-2788", "CVE-2007-2789", "CVE-2007-3655", "CVE-2007-3922");

  script_name(english:"SuSE 10 Security Update : IBM Java 1.4.2 (ZYPP Patch Number 4542)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The IBM Java JRE/SDK has been brought to release 1.4.2 SR9, containing
several bugfixes, including the following security fixes :

  - A buffer overflow vulnerability in the image parsing
    code in the Java(TM) Runtime Environment may allow an
    untrusted applet or application to elevate its
    privileges. For example, an applet may grant itself
    permissions to read and write local files or execute
    local applications that are accessible to the user
    running the untrusted applet. (CVE-2007-2788 /
    CVE-2007-2789 / CVE-2007-3004 / CVE-2007-3005)

    A second vulnerability may allow an untrusted applet or
    application to cause the Java Virtual Machine to hang.

  - A buffer overflow vulnerability in the Java Web Start
    URL parsing code may allow an untrusted application to
    elevate its privileges. For example, an application may
    grant itself permissions to read and write local files
    or execute local applications with the privileges of the
    user running the Java Web Start application.
    (CVE-2007-3655)

  - A security vulnerability in the Java Runtime Environment
    Applet Class Loader may allow an untrusted applet that
    is loaded from a remote system to circumvent network
    access restrictions and establish socket connections to
    certain services running on the local host, as if it
    were loaded from the system that the applet is running
    on. This may allow the untrusted remote applet the
    ability to exploit any security vulnerabilities existing
    in the services it has connected to. (CVE-2007-3922)

For more information see:
http://www-128.ibm.com/developerworks/java/jdk/alerts/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-2788.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-2789.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-3004.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-3005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-3655.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-3922.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 4542.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLES10", sp:1, reference:"java-1_4_2-ibm-1.4.2_sr9-0.2")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"java-1_4_2-ibm-devel-1.4.2_sr9-0.2")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"java-1_4_2-ibm-jdbc-1.4.2_sr9-0.2")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"java-1_4_2-ibm-plugin-1.4.2_sr9-0.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
