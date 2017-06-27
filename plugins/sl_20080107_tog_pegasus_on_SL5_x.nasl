#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60341);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/01/14 15:20:33 $");

  script_cve_id("CVE-2008-0003");

  script_name(english:"Scientific Linux Security Update : tog-pegasus on SL5.x, SL4.x i386/x86_64");
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
"During a security audit, a stack-based buffer overflow flaw was found
in the PAM authentication code in the OpenPegasus CIM management
server. An unauthenticated remote user could trigger this flaw and
potentially execute arbitrary code with root privileges.
(CVE-2008-0003)

Users of tog-pegasus should upgrade to these updated packages, which
contain a backported patch to resolve this issue. After installing the
updated packages the tog-pegasus service should be restarted."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0801&L=scientific-linux-errata&T=0&P=336
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a6008c73"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected tog-pegasus, tog-pegasus-devel and / or
tog-pegasus-test packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL4", cpu:"i386", reference:"tog-pegasus-2.5.1-5.el4_6.1")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"tog-pegasus-2.5.1-5.el4.1")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"tog-pegasus-devel-2.5.1-5.el4_6.1")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"tog-pegasus-devel-2.5.1-5.el4.1")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"tog-pegasus-test-2.5.1-5.el4_6.1")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"tog-pegasus-test-2.5.1-5.el4.1")) flag++;

if (rpm_check(release:"SL5", reference:"tog-pegasus-2.6.1-2.el5_1.1")) flag++;
if (rpm_check(release:"SL5", reference:"tog-pegasus-devel-2.6.1-2.el5_1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
