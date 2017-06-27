#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(92698);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/19 14:25:13 $");

  script_cve_id("CVE-2014-8127", "CVE-2014-8129", "CVE-2014-8130", "CVE-2014-9330", "CVE-2014-9655", "CVE-2015-1547", "CVE-2015-7554", "CVE-2015-8665", "CVE-2015-8668", "CVE-2015-8683", "CVE-2015-8781", "CVE-2015-8782", "CVE-2015-8783", "CVE-2015-8784", "CVE-2016-3632", "CVE-2016-3945", "CVE-2016-3990", "CVE-2016-3991", "CVE-2016-5320");

  script_name(english:"Scientific Linux Security Update : libtiff on SL6.x i386/x86_64");
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

  - Multiple flaws have been discovered in libtiff. A remote
    attacker could exploit these flaws to cause a crash or
    memory corruption and, possibly, execute arbitrary code
    by tricking an application linked against libtiff into
    processing specially crafted files. (CVE-2014-9655,
    CVE-2015-1547, CVE-2015-8784, CVE-2015-8683,
    CVE-2015-8665, CVE-2015-8781, CVE-2015-8782,
    CVE-2015-8783, CVE-2016-3990, CVE-2016-5320)

  - Multiple flaws have been discovered in various libtiff
    tools (bmp2tiff, pal2rgb, thumbnail, tiff2bw, tiff2pdf,
    tiffcrop, tiffdither, tiffsplit, tiff2rgba). By tricking
    a user into processing a specially crafted file, a
    remote attacker could exploit these flaws to cause a
    crash or memory corruption and, possibly, execute
    arbitrary code with the privileges of the user running
    the libtiff tool. (CVE-2014-8127, CVE-2014-8129,
    CVE-2014-8130, CVE-2014-9330, CVE-2015-7554,
    CVE-2015-8668, CVE-2016-3632, CVE-2016-3945,
    CVE-2016-3991)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1608&L=scientific-linux-errata&F=&S=&P=77
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b9c291b3"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/03");
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
if (rpm_check(release:"SL6", reference:"libtiff-3.9.4-18.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"libtiff-debuginfo-3.9.4-18.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"libtiff-devel-3.9.4-18.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"libtiff-static-3.9.4-18.el6_8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
