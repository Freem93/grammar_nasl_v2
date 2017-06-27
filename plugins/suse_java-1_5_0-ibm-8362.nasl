#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(62962);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/11/18 19:12:05 $");

  script_cve_id("CVE-2012-1531", "CVE-2012-3143", "CVE-2012-3216", "CVE-2012-5069", "CVE-2012-5071", "CVE-2012-5073", "CVE-2012-5075", "CVE-2012-5079", "CVE-2012-5081", "CVE-2012-5083", "CVE-2012-5084", "CVE-2012-5089");

  script_name(english:"SuSE 10 Security Update : IBM Java 1.5.0 (ZYPP Patch Number 8362)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"IBM Java 1.5.0 has been updated to SR15 which fixes bugs and security
issues.

More information can be found on :

http://www.ibm.com/developerworks/java/jdk/alerts/

CVE-2012-3216 / CVE-2012-3143 / CVE-2012-5073 / CVE-2012-5075 /
CVE-2012-5083 / CVE-2012-5083 / CVE-2012-1531 / CVE-2012-5081 /
CVE-2012-5069 / CVE-2012-5071 / CVE-2012-5084 / CVE-2012-5079 /
CVE-2012-5089"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1531.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3143.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3216.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5069.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5071.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5073.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5075.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5079.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5081.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5083.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5084.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5089.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 8362.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:4, reference:"java-1_5_0-ibm-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"java-1_5_0-ibm-demo-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"java-1_5_0-ibm-devel-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"java-1_5_0-ibm-fonts-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"java-1_5_0-ibm-src-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"i586", reference:"java-1_5_0-ibm-alsa-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"i586", reference:"java-1_5_0-ibm-jdbc-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"i586", reference:"java-1_5_0-ibm-plugin-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"java-1_5_0-ibm-32bit-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"java-1_5_0-ibm-alsa-32bit-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"java-1_5_0-ibm-devel-32bit-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"java-1_5_0-ibm-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"java-1_5_0-ibm-devel-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"java-1_5_0-ibm-fonts-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"java-1_5_0-ibm-alsa-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"java-1_5_0-ibm-jdbc-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"java-1_5_0-ibm-plugin-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"java-1_5_0-ibm-32bit-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"java-1_5_0-ibm-alsa-32bit-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"java-1_5_0-ibm-devel-32bit-1.5.0_sr15.0-0.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
