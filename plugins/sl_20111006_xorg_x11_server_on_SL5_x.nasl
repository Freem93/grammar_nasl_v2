#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61151);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/09/07 10:52:22 $");

  script_cve_id("CVE-2010-4818", "CVE-2010-4819");

  script_name(english:"Scientific Linux Security Update : xorg-x11-server on SL5.x, SL6.x i386/x86_64");
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
"X.Org is an open source implementation of the X Window System. It
provides the basic low-level functionality that full-fledged graphical
user interfaces are designed upon.

Multiple input sanitization flaws were found in the X.Org GLX (OpenGL
extension to the X Window System) extension. A malicious, authorized
client could use these flaws to crash the X.Org server or,
potentially, execute arbitrary code with root privileges.
(CVE-2010-4818)

An input sanitization flaw was found in the X.Org Render extension. A
malicious, authorized client could use this flaw to leak arbitrary
memory from the X.Org server process, or possibly crash the X.Org
server. (CVE-2010-4819)

Users of xorg-x11-server should upgrade to these updated packages,
which contain backported patches to resolve these issues. All running
X.Org server instances must be restarted for this update to take
effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1110&L=scientific-linux-errata&T=0&P=821
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b57ab833"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"xorg-x11-server-Xdmx-1.1.1-48.76.el5_7.5")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-Xephyr-1.1.1-48.76.el5_7.5")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-Xnest-1.1.1-48.76.el5_7.5")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-Xorg-1.1.1-48.76.el5_7.5")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-Xvfb-1.1.1-48.76.el5_7.5")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-Xvnc-source-1.1.1-48.76.el5_7.5")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-debuginfo-1.1.1-48.76.el5_7.5")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-sdk-1.1.1-48.76.el5_7.5")) flag++;

if (rpm_check(release:"SL6", reference:"xorg-x11-server-Xdmx-1.7.7-29.el6_1.2")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-Xephyr-1.7.7-29.el6_1.2")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-Xnest-1.7.7-29.el6_1.2")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-Xorg-1.7.7-29.el6_1.2")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-Xvfb-1.7.7-29.el6_1.2")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-common-1.7.7-29.el6_1.2")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-debuginfo-1.7.7-29.el6_1.2")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-devel-1.7.7-29.el6_1.2")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-source-1.7.7-29.el6_1.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
