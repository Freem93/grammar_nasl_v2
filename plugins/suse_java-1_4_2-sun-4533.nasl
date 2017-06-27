#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(29473);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2012/05/17 11:12:38 $");

  script_cve_id("CVE-2007-5232", "CVE-2007-5236", "CVE-2007-5237", "CVE-2007-5238", "CVE-2007-5239", "CVE-2007-5240", "CVE-2007-5273", "CVE-2007-5274");

  script_name(english:"SuSE 10 Security Update : Sun Java 1.4.2 (ZYPP Patch Number 4533)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Sun JAVA JDK 1.4.2 was upgraded to release 16 to fix various bugs,
including the following security bugs :

http://sunsolve.sun.com/search/document.do?assetkey=1-26-103079-1

  - Sun Java Runtime Environment (JRE) in JDK and JRE 6
    Update 2 and earlier, JDK and JRE 5.0 Update 12 and
    earlier, SDK and JRE 1.4.2_15 and earlier, and SDK and
    JRE 1.3.1_20 and earlier, when applet caching is
    enabled, allows remote attackers to violate the security
    model for an applet's outbound connections via a DNS
    rebinding attack. (CVE-2007-5232)

http://sunsolve.sun.com/search/document.do?assetkey=1-26-103073-1

  - Java Web Start in Sun JDK and JRE 5.0 Update 12 and
    earlier, and SDK and JRE 1.4.2_15 and earlier, on
    Windows does not properly enfor ce access restrictions
    for untrusted applications, which allows user-assisted
    remote attackers to read local files via an untrusted
    applica tion. (CVE-2007-5236)

  - Java Web Start in Sun JDK and JRE 6 Update 2 and earlier
    does not properly enforce access restrictions for
    untrusted applications, which allows user-assisted
    remote attackers to read and modify local files via an
    untrusted application, aka 'two vulnerabilities'.
    (CVE-2007-5237)

  - Java Web Start in Sun JDK and JRE 6 Update 2 and
    earlier, JDK and JRE 5.0 Update 12 and earlier, and SDK
    and JRE 1.4.2_15 and earlier does not properly enforce
    access restrictions for untrusted applications, which
    allows user-assisted remote attackers to obtain
    sensitive information (the Java Web Start cache
    location) via an untrusted application, aka 'three
    vulnerabilities.'. (CVE-2007-5238)

http://sunsolve.sun.com/search/document.do?assetkey=1-26-103072-1

  - Java Web Start in Sun JDK and JRE 6 Update 2 and
    earlier, JDK and JRE 5.0 Update 12 and earlier, SDK and
    JRE 1.4.2_15 and earlier, and SDK and JRE 1.3.1_20 and
    earlier does not properly enforce access restrictions
    for untrusted (1) applications and (2) applets, which
    allows user-assisted remote attackers to copy or rename
    arbitrary files when local users perform drag-and-drop
    operations from the untrusted application or applet
    window onto certain types of desktop applications.
    (CVE-2007-5239)

http://sunsolve.sun.com/search/document.do?assetkey=1-26-103071-1

  - Visual truncation vulnerability in the Java Runtime
    Environment in Sun JDK and JRE 6 Update 2 and earlier,
    JDK and JRE 5.0 Update 12 and earlier, SDK and JRE
    1.4.2_15 and earlier, and SDK and JRE 1.3.1_20 and
    earlier allows remote attackers to circumvent display of
    the untrusted-code warning banner by creating a window
    larger than the workstation screen. (CVE-2007-5240)

http://sunsolve.sun.com/search/document.do?assetkey=1-26-103078-1

  - Sun Java Runtime Environment (JRE) in JDK and JRE 6
    Update 2 and earlier, JDK and JRE 5.0 Update 12 and
    earlier, SDK and JRE 1.4.2_15 and earlier, and SDK and
    JRE 1.3.1_20 and earlier, when an HTTP proxy server is
    used, allows remote attackers to violate the security
    model for an applet's outbound connections via a
    multi-pin DNS rebinding attack in which the applet
    download relies on DNS resolution on the proxy server,
    but the applet's socket operations rely on DNS
    resolution on the local machine, a different issue than
    CVE-2007-5274. (CVE-2007-5273)

  - Sun Java Runtime Environment (JRE) in JDK and JRE 6
    Update 2 and earlier, JDK and JRE 5.0 Update 12 and
    earlier, SDK and JRE 1.4.2_15 and earlier, and SDK and
    JRE 1.3.1_20 and earlier, when Firefox or Opera is used,
    allows remote attackers to violate the security model
    for JavaScript outbound connections via a multi-pin DNS
    rebinding attack dependent on the LiveConnect API, in
    which JavaScript download relies on DNS resolution by
    the browser, but JavaScript socket operations rely on
    separate DNS resolution by a Java Virtual Machine (JVM),
    a different issue than CVE-2007-5273. (CVE-2007-5274)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-5232.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-5236.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-5237.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-5238.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-5239.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-5240.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-5273.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-5274.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 4533.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:1, reference:"java-1_4_2-sun-1.4.2.16-0.2")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"java-1_4_2-sun-alsa-1.4.2.16-0.2")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"java-1_4_2-sun-demo-1.4.2.16-0.2")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"java-1_4_2-sun-devel-1.4.2.16-0.2")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"java-1_4_2-sun-jdbc-1.4.2.16-0.2")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"java-1_4_2-sun-plugin-1.4.2.16-0.2")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"java-1_4_2-sun-src-1.4.2.16-0.2")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"java-1_4_2-sun-1.4.2.16-0.2")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"java-1_4_2-sun-alsa-1.4.2.16-0.2")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"java-1_4_2-sun-devel-1.4.2.16-0.2")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"java-1_4_2-sun-jdbc-1.4.2.16-0.2")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"java-1_4_2-sun-plugin-1.4.2.16-0.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
