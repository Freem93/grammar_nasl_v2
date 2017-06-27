#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(29472);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/22 20:32:46 $");

  script_cve_id("CVE-2007-0243", "CVE-2007-2788", "CVE-2007-2789");

  script_name(english:"SuSE 10 Security Update : Java (ZYPP Patch Number 3844)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Sun JAVA JDK 1.4.2 was upgraded to release 15 to fix various bugs,
including the following security bugs :

  - Integer overflow in the embedded ICC profile image
    parser in Sun Java Development Kit (JDK), allows remote
    attackers to execute arbitrary code or cause a denial of
    service (JVM crash) via a crafted JPEG or BMP file.
    (CVE-2007-2788 / CVE-2007-3004)

  - The BMP image parser in Sun Java Development Kit (JDK),
    on Unix/Linux systems, allows remote attackers to
    trigger the opening of arbitrary local files via a
    crafted BMP file, which causes a denial of service
    (system hang) in certain cases such as /dev/tty, and has
    other unspecified impact. (CVE-2007-2789 /
    CVE-2007-3005)

  - Buffer overflow in Sun JDK and Java Runtime Environment
    (JRE) allows applets to gain privileges via a GIF image
    with a block with a 0 width field, which triggers memory
    corruption. (CVE-2007-0243)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-0243.html"
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
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 3844.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/05");
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
if (rpm_check(release:"SLED10", sp:1, reference:"java-1_4_2-sun-1.4.2.15-2.1")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"java-1_4_2-sun-alsa-1.4.2.15-2.1")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"java-1_4_2-sun-demo-1.4.2.15-2.1")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"java-1_4_2-sun-devel-1.4.2.15-2.1")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"java-1_4_2-sun-jdbc-1.4.2.15-2.1")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"java-1_4_2-sun-plugin-1.4.2.15-2.1")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"java-1_4_2-sun-src-1.4.2.15-2.1")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"java-1_4_2-sun-1.4.2.15-2.1")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"java-1_4_2-sun-alsa-1.4.2.15-2.1")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"java-1_4_2-sun-devel-1.4.2.15-2.1")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"java-1_4_2-sun-jdbc-1.4.2.15-2.1")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"java-1_4_2-sun-plugin-1.4.2.15-2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
