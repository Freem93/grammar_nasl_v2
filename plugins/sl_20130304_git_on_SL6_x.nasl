#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(65018);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/04/06 01:08:36 $");

  script_cve_id("CVE-2013-0308");

  script_name(english:"Scientific Linux Security Update : git on SL6.x i386/x86_64");
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
"It was discovered that Git's git-imap-send command, a tool to send a
collection of patches from standard input (stdin) to an IMAP folder,
did not properly perform SSL X.509 v3 certificate validation on the
IMAP server's certificate, as it did not ensure that the server's
hostname matched the one provided in the CN field of the server's
certificate. A rogue server could use this flaw to conduct
man-in-the-middle attacks, possibly leading to the disclosure of
sensitive information. (CVE-2013-0308)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1303&L=scientific-linux-errata&T=0&P=1680
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?477c55a8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"emacs-git-1.7.1-3.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"emacs-git-el-1.7.1-3.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"git-1.7.1-3.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"git-all-1.7.1-3.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"git-cvs-1.7.1-3.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"git-daemon-1.7.1-3.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"git-debuginfo-1.7.1-3.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"git-email-1.7.1-3.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"git-gui-1.7.1-3.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"git-svn-1.7.1-3.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"gitk-1.7.1-3.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"gitweb-1.7.1-3.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"perl-Git-1.7.1-3.el6_4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
