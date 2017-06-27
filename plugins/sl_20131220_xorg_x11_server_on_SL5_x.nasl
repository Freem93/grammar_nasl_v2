#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(71631);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/05/22 11:17:46 $");

  script_cve_id("CVE-2013-6424");

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
"An integer overflow, which led to a heap-based buffer overflow, was
found in the way X.Org server handled trapezoids. A malicious,
authorized client could use this flaw to crash the X.Org server or,
potentially, execute arbitrary code with root privileges.
(CVE-2013-6424)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1312&L=scientific-linux-errata&T=0&P=5435
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8670fb94"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"xorg-x11-server-Xdmx-1.1.1-48.101.el5_10.2")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-Xephyr-1.1.1-48.101.el5_10.2")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-Xnest-1.1.1-48.101.el5_10.2")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-Xorg-1.1.1-48.101.el5_10.2")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-Xvfb-1.1.1-48.101.el5_10.2")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-Xvnc-source-1.1.1-48.101.el5_10.2")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-debuginfo-1.1.1-48.101.el5_10.2")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-sdk-1.1.1-48.101.el5_10.2")) flag++;

if (rpm_check(release:"SL6", reference:"xorg-x11-server-Xdmx-1.13.0-23.1.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-Xephyr-1.13.0-23.1.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-Xnest-1.13.0-23.1.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-Xorg-1.13.0-23.1.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-Xvfb-1.13.0-23.1.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-common-1.13.0-23.1.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-debuginfo-1.13.0-23.1.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-devel-1.13.0-23.1.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-source-1.13.0-23.1.el6_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
