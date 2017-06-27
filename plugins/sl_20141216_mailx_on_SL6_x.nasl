#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(80075);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/12/30 13:38:09 $");

  script_cve_id("CVE-2004-2771", "CVE-2014-7844");

  script_name(english:"Scientific Linux Security Update : mailx on SL6.x, SL7.x i386/x86_64");
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
"A flaw was found in the way mailx handled the parsing of email
addresses. A syntactically valid email address could allow a local
attacker to cause mailx to execute arbitrary shell commands through
shell meta-characters and the direct command execution functionality.
(CVE-2004-2771, CVE-2014-7844)

Note: Applications using mailx to send email to addresses obtained
from untrusted sources will still remain vulnerable to other attacks
if they accept email addresses which start with '-' (so that they can
be confused with mailx options). To counteract this issue, this update
also introduces the '--' option, which will treat the remaining
command line arguments as email addresses."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1412&L=scientific-linux-errata&T=0&P=2833
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?03d706d8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mailx and / or mailx-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"mailx-12.4-8.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"mailx-debuginfo-12.4-8.el6_6")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mailx-12.5-12.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mailx-debuginfo-12.5-12.el7_0")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");