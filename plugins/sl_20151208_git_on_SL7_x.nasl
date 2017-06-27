#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(87582);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/12/22 15:46:34 $");

  script_name(english:"Scientific Linux Security Update : git on SL7.x x86_64");
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
"A flaw was found in the way the git-remote-ext helper processed
certain URLs. If a user had Git configured to automatically clone
submodules from untrusted repositories, an attacker could inject
commands into the URL of a submodule, allowing them to execute
arbitrary code on the user's system."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1512&L=scientific-linux-errata&F=&S=&P=18147
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?30ec60db"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/22");
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
if (rpm_check(release:"SL7", reference:"emacs-git-1.8.3.1-6.el7")) flag++;
if (rpm_check(release:"SL7", reference:"emacs-git-el-1.8.3.1-6.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"git-1.8.3.1-6.el7")) flag++;
if (rpm_check(release:"SL7", reference:"git-all-1.8.3.1-6.el7")) flag++;
if (rpm_check(release:"SL7", reference:"git-bzr-1.8.3.1-6.el7")) flag++;
if (rpm_check(release:"SL7", reference:"git-cvs-1.8.3.1-6.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"git-daemon-1.8.3.1-6.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"git-debuginfo-1.8.3.1-6.el7")) flag++;
if (rpm_check(release:"SL7", reference:"git-email-1.8.3.1-6.el7")) flag++;
if (rpm_check(release:"SL7", reference:"git-gui-1.8.3.1-6.el7")) flag++;
if (rpm_check(release:"SL7", reference:"git-hg-1.8.3.1-6.el7")) flag++;
if (rpm_check(release:"SL7", reference:"git-p4-1.8.3.1-6.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"git-svn-1.8.3.1-6.el7")) flag++;
if (rpm_check(release:"SL7", reference:"gitk-1.8.3.1-6.el7")) flag++;
if (rpm_check(release:"SL7", reference:"gitweb-1.8.3.1-6.el7")) flag++;
if (rpm_check(release:"SL7", reference:"perl-Git-1.8.3.1-6.el7")) flag++;
if (rpm_check(release:"SL7", reference:"perl-Git-SVN-1.8.3.1-6.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
