#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(91806);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2017/04/18 13:37:17 $");

  script_cve_id("CVE-2016-4444", "CVE-2016-4445", "CVE-2016-4446", "CVE-2016-4989");

  script_name(english:"Scientific Linux Security Update : setroubleshoot and setroubleshoot-plugins on SL6.x i386/x86_64");
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
"The setroubleshoot-plugins package provides a set of analysis plugins
for use with setroubleshoot. Each plugin has the capacity to analyze
SELinux AVC data and system data to provide user friendly reports
describing how to interpret SELinux AVC denials.

Security Fix(es) :

  - Shell command injection flaws were found in the way the
    setroubleshoot executed external commands. A local
    attacker able to trigger certain SELinux denials could
    use these flaws to execute arbitrary code with root
    privileges. (CVE-2016-4445, CVE-2016-4989)

  - Shell command injection flaws were found in the way the
    setroubleshoot allow_execmod and allow_execstack plugins
    executed external commands. A local attacker able to
    trigger an execmod or execstack SELinux denial could use
    these flaws to execute arbitrary code with root
    privileges. (CVE-2016-4444, CVE-2016-4446)

The CVE-2016-4444 and CVE-2016-4446 issues were discovered by Milos
Malik (Red Hat) and the CVE-2016-4445 and CVE-2016-4989 issues were
discovered by Red Hat Product Security."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1606&L=scientific-linux-errata&F=&S=&P=7583
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2dee5a20"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"setroubleshoot-3.0.47-12.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"setroubleshoot-debuginfo-3.0.47-12.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"setroubleshoot-doc-3.0.47-12.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"setroubleshoot-plugins-3.0.40-3.1.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"setroubleshoot-server-3.0.47-12.el6_8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
