#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61252);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/08/08 14:30:48 $");

  script_cve_id("CVE-2011-3563", "CVE-2011-3571", "CVE-2011-5035", "CVE-2012-0498", "CVE-2012-0499", "CVE-2012-0500", "CVE-2012-0501", "CVE-2012-0502", "CVE-2012-0503", "CVE-2012-0505", "CVE-2012-0506");

  script_name(english:"Scientific Linux Security Update : java-1.6.0-sun on SL4.x, SL5.x i386/x86_64");
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
"This update fixes several vulnerabilities in the Sun Java 6 Runtime
Environment and the Sun Java 6 Software Development Kit. Further
information about these flaws can be found on the Oracle Java SE
Critical Patch page. (CVE-2011-3563, CVE-2011-3571, CVE-2011-5035,
CVE-2012-0498, CVE-2012-0499, CVE-2012-0500, CVE-2012-0501,
CVE-2012-0502, CVE-2012-0503, CVE-2012-0505, CVE-2012-0506)

All users of java-1.6.0-sun are advised to upgrade to these updated
packages, which provide JDK and JRE 6 Update 31 and resolve these
issues. All running instances of Sun Java must be restarted for the
update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1202&L=scientific-linux-errata&T=0&P=4038
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a778edcc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.6.0-sun-compat and / or jdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java Web Start Plugin Command Line Argument Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL4", reference:"java-1.6.0-sun-compat-1.6.0.31-3.sl4.jpp")) flag++;
if (rpm_check(release:"SL4", reference:"jdk-1.6.0_31-fcs")) flag++;

if (rpm_check(release:"SL5", reference:"java-1.6.0-sun-compat-1.6.0.31-3.sl5.jpp")) flag++;
if (rpm_check(release:"SL5", reference:"jdk-1.6.0_31-fcs")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
