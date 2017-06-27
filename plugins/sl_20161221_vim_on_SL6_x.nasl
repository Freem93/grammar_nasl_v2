#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(96044);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2016/12/21 20:33:29 $");

  script_cve_id("CVE-2016-1248");

  script_name(english:"Scientific Linux Security Update : vim on SL6.x, SL7.x i386/x86_64");
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
"Security Fix(es) :

  - A vulnerability was found in vim in how certain modeline
    options were treated. An attacker could craft a file
    that, when opened in vim with modelines enabled, could
    execute arbitrary commands with privileges of the user
    running vim. (CVE-2016-1248)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1612&L=scientific-linux-errata&F=&S=&P=18621
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?841e0bd3"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"vim-X11-7.4.629-5.el6_8.1")) flag++;
if (rpm_check(release:"SL6", reference:"vim-common-7.4.629-5.el6_8.1")) flag++;
if (rpm_check(release:"SL6", reference:"vim-debuginfo-7.4.629-5.el6_8.1")) flag++;
if (rpm_check(release:"SL6", reference:"vim-enhanced-7.4.629-5.el6_8.1")) flag++;
if (rpm_check(release:"SL6", reference:"vim-filesystem-7.4.629-5.el6_8.1")) flag++;
if (rpm_check(release:"SL6", reference:"vim-minimal-7.4.629-5.el6_8.1")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"vim-X11-7.4.160-1.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"vim-common-7.4.160-1.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"vim-debuginfo-7.4.160-1.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"vim-enhanced-7.4.160-1.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"vim-filesystem-7.4.160-1.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"vim-minimal-7.4.160-1.el7_3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
