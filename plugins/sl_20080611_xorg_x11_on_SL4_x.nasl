#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60422);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:53 $");

  script_cve_id("CVE-2008-1377", "CVE-2008-1379", "CVE-2008-2360", "CVE-2008-2361");

  script_name(english:"Scientific Linux Security Update : xorg-x11 on SL4.x i386/x86_64");
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
"An input validation flaw was discovered in X.org's Security and Record
extensions. A malicious authorized client could exploit this issue to
cause a denial of service (crash) or, potentially, execute arbitrary
code with root privileges on the X.Org server. (CVE-2008-1377)

Multiple integer overflow flaws were found in X.org's Render
extension. A malicious authorized client could exploit these issues to
cause a denial of service (crash) or, potentially, execute arbitrary
code with root privileges on the X.Org server. (CVE-2008-2360,
CVE-2008-2361)

An input validation flaw was discovered in X.org's MIT-SHM extension.
A client connected to the X.org server could read arbitrary server
memory. This could result in the sensitive data of other users of the
X.org server being disclosed. (CVE-2008-1379)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0806&L=scientific-linux-errata&T=0&P=1369
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d048f04e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/11");
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
if (rpm_check(release:"SL4", reference:"xorg-x11-6.8.2-1.EL.33.0.4")) flag++;
if (rpm_check(release:"SL4", reference:"xorg-x11-Mesa-libGL-6.8.2-1.EL.33.0.4")) flag++;
if (rpm_check(release:"SL4", reference:"xorg-x11-Mesa-libGLU-6.8.2-1.EL.33.0.4")) flag++;
if (rpm_check(release:"SL4", reference:"xorg-x11-Xdmx-6.8.2-1.EL.33.0.4")) flag++;
if (rpm_check(release:"SL4", reference:"xorg-x11-Xnest-6.8.2-1.EL.33.0.4")) flag++;
if (rpm_check(release:"SL4", reference:"xorg-x11-Xvfb-6.8.2-1.EL.33.0.4")) flag++;
if (rpm_check(release:"SL4", reference:"xorg-x11-deprecated-libs-6.8.2-1.EL.33.0.4")) flag++;
if (rpm_check(release:"SL4", reference:"xorg-x11-deprecated-libs-devel-6.8.2-1.EL.33.0.4")) flag++;
if (rpm_check(release:"SL4", reference:"xorg-x11-devel-6.8.2-1.EL.33.0.4")) flag++;
if (rpm_check(release:"SL4", reference:"xorg-x11-doc-6.8.2-1.EL.33.0.4")) flag++;
if (rpm_check(release:"SL4", reference:"xorg-x11-font-utils-6.8.2-1.EL.33.0.4")) flag++;
if (rpm_check(release:"SL4", reference:"xorg-x11-libs-6.8.2-1.EL.33.0.4")) flag++;
if (rpm_check(release:"SL4", reference:"xorg-x11-sdk-6.8.2-1.EL.33.0.4")) flag++;
if (rpm_check(release:"SL4", reference:"xorg-x11-tools-6.8.2-1.EL.33.0.4")) flag++;
if (rpm_check(release:"SL4", reference:"xorg-x11-twm-6.8.2-1.EL.33.0.4")) flag++;
if (rpm_check(release:"SL4", reference:"xorg-x11-xauth-6.8.2-1.EL.33.0.4")) flag++;
if (rpm_check(release:"SL4", reference:"xorg-x11-xdm-6.8.2-1.EL.33.0.4")) flag++;
if (rpm_check(release:"SL4", reference:"xorg-x11-xfs-6.8.2-1.EL.33.0.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
