#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(64423);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/03/20 10:49:03 $");

  script_cve_id("CVE-2012-5659", "CVE-2012-5660");

  script_name(english:"Scientific Linux Security Update : abrt and libreport on SL6.x i386/x86_64");
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
"It was found that the
/usr/libexec/abrt-action-install-debuginfo-to-abrt-cache tool did not
sufficiently sanitize its environment variables. This could lead to
Python modules being loaded and run from non-standard directories
(such as /tmp/). A local attacker could use this flaw to escalate
their privileges to that of the abrt user. (CVE-2012-5659)

A race condition was found in the way ABRT handled the directories
used to store information about crashes. A local attacker with the
privileges of the abrt user could use this flaw to perform a symbolic
link attack, possibly allowing them to escalate their privileges to
root. (CVE-2012-5660)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1302&L=scientific-linux-errata&T=0&P=465
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0b33fdd3"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/04");
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
if (rpm_check(release:"SL6", reference:"abrt-2.0.8-6.el6_3.2")) flag++;
if (rpm_check(release:"SL6", reference:"abrt-addon-ccpp-2.0.8-6.el6_3.2")) flag++;
if (rpm_check(release:"SL6", reference:"abrt-addon-kerneloops-2.0.8-6.el6_3.2")) flag++;
if (rpm_check(release:"SL6", reference:"abrt-addon-python-2.0.8-6.el6_3.2")) flag++;
if (rpm_check(release:"SL6", reference:"abrt-addon-vmcore-2.0.8-6.el6_3.2")) flag++;
if (rpm_check(release:"SL6", reference:"abrt-cli-2.0.8-6.el6_3.2")) flag++;
if (rpm_check(release:"SL6", reference:"abrt-debuginfo-2.0.8-6.el6_3.2")) flag++;
if (rpm_check(release:"SL6", reference:"abrt-desktop-2.0.8-6.el6_3.2")) flag++;
if (rpm_check(release:"SL6", reference:"abrt-devel-2.0.8-6.el6_3.2")) flag++;
if (rpm_check(release:"SL6", reference:"abrt-gui-2.0.8-6.el6_3.2")) flag++;
if (rpm_check(release:"SL6", reference:"abrt-libs-2.0.8-6.el6_3.2")) flag++;
if (rpm_check(release:"SL6", reference:"abrt-tui-2.0.8-6.el6_3.2")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-2.0.9-5.el6_3.2")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-cli-2.0.9-5.el6_3.2")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-debuginfo-2.0.9-5.el6_3.2")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-devel-2.0.9-5.el6_3.2")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-gtk-2.0.9-5.el6_3.2")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-gtk-devel-2.0.9-5.el6_3.2")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-newt-2.0.9-5.el6_3.2")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-plugin-bugzilla-2.0.9-5.el6_3.2")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-plugin-kerneloops-2.0.9-5.el6_3.2")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-plugin-logger-2.0.9-5.el6_3.2")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-plugin-mailx-2.0.9-5.el6_3.2")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-plugin-reportuploader-2.0.9-5.el6_3.2")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-plugin-rhtsupport-2.0.9-5.el6_3.2")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-python-2.0.9-5.el6_3.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
