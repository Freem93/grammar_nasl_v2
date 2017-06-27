#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41258);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/21 20:33:29 $");

  script_cve_id("CVE-2008-3104", "CVE-2008-3112", "CVE-2008-3113", "CVE-2008-3114");

  script_name(english:"SuSE9 Security Update : IBM Java2 JRE and SDK (YOU Patch Number 12313)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 9 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"IBM Java 1.4.2 SR12 fixes the following security problems :

  - Security vulnerabilities in the Java Runtime Environment
    may allow an untrusted applet that is loaded from a
    remote system to circumvent network access restrictions
    and establish socket connections to certain services
    running on the local host, as if it were loaded from the
    system that the applet is running on. This may allow the
    untrusted remote applet the ability to exploit any
    security vulnerabilities existing in the services it has
    connected to. (CVE-2008-3104)

  - A vulnerability in Java Web Start may allow an untrusted
    Java Web Start application downloaded from a website to
    create arbitrary files with the permissions of the user
    running the untrusted Java Web Start application.
    (CVE-2008-3112)

  - A vulnerability in Java Web Start may allow an untrusted
    Java Web Start application downloaded from a website to
    create or delete arbitrary files with the permissions of
    the user running the untrusted Java Web Start
    application. (CVE-2008-3113)

  - A vulnerability in Java Web Start may allow an untrusted
    Java Web Start application to determine the location of
    the Java Web Start cache. (CVE-2008-3114)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-3104.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-3112.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-3113.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-3114.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply YOU patch number 12313.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/27");
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
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"IBMJava2-JRE-1.4.2-0.131")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"IBMJava2-SDK-1.4.2-0.131")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"IBMJava2-JRE-1.4.2-0.129")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"IBMJava2-SDK-1.4.2-0.129")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
