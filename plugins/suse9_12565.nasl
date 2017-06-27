#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43854);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/21 20:33:29 $");

  script_cve_id("CVE-2009-3867", "CVE-2009-3869", "CVE-2009-3871", "CVE-2009-3874", "CVE-2009-3875");

  script_name(english:"SuSE9 Security Update : IBM Java2 JRE and SDK (YOU Patch Number 12565)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 9 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"IBM Java 1.4.2 was updated to 13 fp3.

The following security issues were fixed :

  - A buffer overflow vulnerability in the Java Runtime
    Environment audio system might allow an untrusted applet
    or Java Web Start application to escalate privileges.
    For example, an untrusted applet might grant itself
    permissions to read and write local files, or run local
    applications that are accessible to the user running the
    untrusted applet. (CVE-2009-3867)

  - A security vulnerability in the Java Runtime Environment
    with verifying HMAC digests might allow authentication
    to be bypassed. This action can allow a user to forge a
    digital signature that would be accepted as valid.
    Applications that validate HMAC-based digital signatures
    might be vulnerable to this type of attack.
    (CVE-2009-3875)

  - A buffer overflow vulnerability in the Java Runtime
    Environment with processing image files might allow an
    untrusted applet or Java Web Start application to
    escalate privileges. For example, an untrusted applet
    might grant itself permissions to read and write local
    files or run local applications that are accessible to
    the user running the untrusted applet. (CVE-2009-3869)

  - A buffer overflow vulnerability in the Java Runtime
    Environment with processing image files might allow an
    untrusted applet or Java Web Start application to
    escalate privileges. For example, an untrusted applet
    might grant itself permissions to read and write local
    files or run local applications that are accessible to
    the user running the untrusted applet. (CVE-2009-3871)

  - An integer overflow vulnerability in the Java Runtime
    Environment with processing JPEG images might allow an
    untrusted applet or Java Web Start application to
    escalate privileges. For example, an untrusted applet
    might grant itself permissions to read and write local
    files or run local applications that are accessible to
    the user running the untrusted applet. (CVE-2009-3874)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3867.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3869.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3871.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3874.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3875.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply YOU patch number 12565.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java JRE AWT setDiffICM Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(119, 189, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SUSE9", reference:"IBMJava2-JRE-1.4.2_sr13.3-0.7")) flag++;
if (rpm_check(release:"SUSE9", reference:"IBMJava2-SDK-1.4.2_sr13.3-0.7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
