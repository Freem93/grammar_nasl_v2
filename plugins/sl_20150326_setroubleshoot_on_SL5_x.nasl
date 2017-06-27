#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(82294);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/04/01 13:32:21 $");

  script_cve_id("CVE-2015-1815");

  script_name(english:"Scientific Linux Security Update : setroubleshoot on SL5.x, SL6.x, SL7.x i386/x86_64");
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
"It was found that setroubleshoot did not sanitize file names supplied
in a shell command look-up for RPMs associated with access violation
reports. An attacker could use this flaw to escalate their privileges
on the system by supplying a specially crafted file to the underlying
shell command. (CVE-2015-1815)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1503&L=scientific-linux-errata&T=0&P=3858
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ecfe0c2f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"setroubleshoot-2.0.5-7.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"setroubleshoot-server-2.0.5-7.el5_11")) flag++;

if (rpm_check(release:"SL6", reference:"setroubleshoot-3.0.47-6.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"setroubleshoot-debuginfo-3.0.47-6.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"setroubleshoot-doc-3.0.47-6.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"setroubleshoot-server-3.0.47-6.el6_6.1")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"setroubleshoot-3.2.17-4.1.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"setroubleshoot-debuginfo-3.2.17-4.1.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"setroubleshoot-server-3.2.17-4.1.el7_1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
