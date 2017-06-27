#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61605);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/16 19:47:28 $");

  script_cve_id("CVE-2009-3909", "CVE-2011-2896", "CVE-2012-3402", "CVE-2012-3403", "CVE-2012-3481");
  script_osvdb_id(60178, 74539);

  script_name(english:"Scientific Linux Security Update : gimp on SL5.x i386/x86_64");
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
"The GIMP (GNU Image Manipulation Program) is an image composition and
editing program.

Multiple integer overflow flaws, leading to heap-based buffer
overflows, were found in the GIMP's Adobe Photoshop (PSD) image file
plug-in. An attacker could create a specially crafted PSD image file
that, when opened, could cause the PSD plug-in to crash or,
potentially, execute arbitrary code with the privileges of the user
running the GIMP. (CVE-2009-3909, CVE-2012-3402)

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the GIMP's GIF image format plug-in. An attacker could create
a specially crafted GIF image file that, when opened, could cause the
GIF plug-in to crash or, potentially, execute arbitrary code with the
privileges of the user running the GIMP. (CVE-2012-3481)

A heap-based buffer overflow flaw was found in the Lempel-Ziv-Welch
(LZW) decompression algorithm implementation used by the GIMP's GIF
image format plug-in. An attacker could create a specially crafted GIF
image file that, when opened, could cause the GIF plug-in to crash or,
potentially, execute arbitrary code with the privileges of the user
running the GIMP. (CVE-2011-2896)

A heap-based buffer overflow flaw was found in the GIMP's KiSS CEL
file format plug-in. An attacker could create a specially crafted KiSS
palette file that, when opened, could cause the CEL plug-in to crash
or, potentially, execute arbitrary code with the privileges of the
user running the GIMP. (CVE-2012-3403)

Users of the GIMP are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The GIMP
must be restarted for the update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1208&L=scientific-linux-errata&T=0&P=1841
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?20875df8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gimp, gimp-devel and / or gimp-libs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/21");
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
if (rpm_check(release:"SL5", reference:"gimp-2.2.13-2.0.7.el5_8.5")) flag++;
if (rpm_check(release:"SL5", reference:"gimp-devel-2.2.13-2.0.7.el5_8.5")) flag++;
if (rpm_check(release:"SL5", reference:"gimp-libs-2.2.13-2.0.7.el5_8.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
