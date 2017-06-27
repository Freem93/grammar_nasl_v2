#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(79330);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/11/19 11:17:57 $");

  script_cve_id("CVE-2014-0209", "CVE-2014-0210", "CVE-2014-0211");

  script_name(english:"Scientific Linux Security Update : libXfont on SL6.x, SL7.x i386/srpm/x86_64");
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
"A use-after-free flaw was found in the way libXfont processed certain
font files when attempting to add a new directory to the font path. A
malicious, local user could exploit this issue to potentially execute
arbitrary code with the privileges of the X.Org server.
(CVE-2014-0209)

Multiple out-of-bounds write flaws were found in the way libXfont
parsed replies received from an X.org font server. A malicious X.org
server could cause an X client to crash or, possibly, execute
arbitrary code with the privileges of the X.Org server.
(CVE-2014-0210, CVE-2014-0211)

All running X.Org server instances must be restarted for the update to
take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1411&L=scientific-linux-errata&T=0&P=3802
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7d6c59c0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected libXfont, libXfont-debuginfo and / or
libXfont-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/19");
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
if (rpm_check(release:"SL6", reference:"libXfont-1.4.5-4.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"libXfont-debuginfo-1.4.5-4.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"libXfont-debuginfo-1.4.5-4.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"libXfont-devel-1.4.5-4.el6_6")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXfont-1.4.7-2.el7_0")) flag++;
if (rpm_check(release:"SL7", reference:"libXfont-debuginfo-1.4.7-2.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXfont-debuginfo-1.4.7-2.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXfont-devel-1.4.7-2.el7_0")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
