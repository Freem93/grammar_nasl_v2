#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61249);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:47:27 $");

  script_cve_id("CVE-2012-0444");

  script_name(english:"Scientific Linux Security Update : libvorbis on SL4.x, SL5.x, SL6.x i386/x86_64");
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
"The libvorbis packages contain runtime libraries for use in programs
that support Ogg Vorbis. Ogg Vorbis is a fully open, non-proprietary,
patent-and royalty-free, general-purpose compressed audio format.

A heap-based buffer overflow flaw was found in the way the libvorbis
library parsed Ogg Vorbis media files. If a specially crafted Ogg
Vorbis media file was opened by an application using libvorbis, it
could cause the application to crash or, possibly, execute arbitrary
code with the privileges of the user running the application.
(CVE-2012-0444)

Users of libvorbis should upgrade to these updated packages, which
contain a backported patch to correct this issue. The desktop must be
restarted (log out, then log back in) for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1202&L=scientific-linux-errata&T=0&P=3058
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8d7167a9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL4", reference:"libvorbis-1.1.0-4.el4.5")) flag++;
if (rpm_check(release:"SL4", reference:"libvorbis-debuginfo-1.1.0-4.el4.5")) flag++;
if (rpm_check(release:"SL4", reference:"libvorbis-devel-1.1.0-4.el4.5")) flag++;

if (rpm_check(release:"SL5", reference:"libvorbis-1.1.2-3.el5_7.6")) flag++;
if (rpm_check(release:"SL5", reference:"libvorbis-debuginfo-1.1.2-3.el5_7.6")) flag++;
if (rpm_check(release:"SL5", reference:"libvorbis-devel-1.1.2-3.el5_7.6")) flag++;

if (rpm_check(release:"SL6", reference:"libvorbis-1.2.3-4.el6_2.1")) flag++;
if (rpm_check(release:"SL6", reference:"libvorbis-debuginfo-1.2.3-4.el6_2.1")) flag++;
if (rpm_check(release:"SL6", reference:"libvorbis-devel-1.2.3-4.el6_2.1")) flag++;
if (rpm_check(release:"SL6", reference:"libvorbis-devel-docs-1.2.3-4.el6_2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
