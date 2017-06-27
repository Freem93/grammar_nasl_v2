#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29469);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/11/27 17:11:05 $");

  script_cve_id("CVE-2006-6736", "CVE-2006-6737", "CVE-2006-6745", "CVE-2007-0243");

  script_name(english:"SuSE 10 Security Update : IBM Java (ZYPP Patch Number 3851)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The IBM Java JRE/SDK has been brought to release 1.4.2 SR containing
several bugfixes, including following security fixes :

  - A buffer overflow vulnerability in the Java(TM) Runtime
    Environment may allow an untrusted applet to elevate its
    privileges. For example, an applet may grant itself
    permissions to read and write local files or execute
    local applications that are accessible to the user
    running the untrusted applet. (CVE-2007-0243)

  - Two vulnerabilities in the Java Runtime Environment may
    independently allow an untrusted applet to access data
    in other applets. (CVE-2006-6737 / CVE-2006-6736)

  - Two vulnerabilities in the Java(TM) Runtime Environment
    with serialization may independently allow an untrusted
    applet or application to elevate its privileges.
    (CVE-2006-6745)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-6736.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-6737.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-6745.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-0243.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 3851.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES10", sp:1, reference:"java-1_4_2-ibm-1.4.2_sr8-1.2")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"java-1_4_2-ibm-devel-1.4.2_sr8-1.2")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"java-1_4_2-ibm-jdbc-1.4.2_sr8-1.2")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"java-1_4_2-ibm-plugin-1.4.2_sr8-1.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
