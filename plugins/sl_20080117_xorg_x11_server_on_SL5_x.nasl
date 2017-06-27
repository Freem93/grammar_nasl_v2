#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60348);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2007-5760", "CVE-2007-5958", "CVE-2007-6427", "CVE-2007-6428", "CVE-2007-6429");

  script_name(english:"Scientific Linux Security Update : xorg-x11-server on SL5.x i386/x86_64");
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
"Two integer overflow flaws were found in the X.Org server's EVI and
MIT-SHM modules. A malicious authorized client could exploit these
issues to cause a denial of service (crash), or potentially execute
arbitrary code with root privileges on the X.Org server.
(CVE-2007-6429)

A memory corruption flaw was found in the X.Org server's XInput
extension. A malicious authorized client could exploit this issue to
cause a denial of service (crash), or potentially execute arbitrary
code with root privileges on the X.Org server. (CVE-2007-6427)

An input validation flaw was found in the X.Org server's XFree86-Misc
extension. A malicious authorized client could exploit this issue to
cause a denial of service (crash), or potentially execute arbitrary
code with root privileges on the X.Org server. (CVE-2007-5760)

An information disclosure flaw was found in the X.Org server's TOG-CUP
extension. A malicious authorized client could exploit this issue to
cause a denial of service (crash), or potentially view arbitrary
memory content within the X server's address space. (CVE-2007-6428)

A flaw was found in the X.Org server's XC-SECURITY extension, that
could have allowed a local user to verify the existence of an
arbitrary file, even in directories that are not normally accessible
to that user. (CVE-2007-5958)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0801&L=scientific-linux-errata&T=0&P=1227
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6d22c6e0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(189, 200, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"xorg-x11-server-Xdmx-1.1.1-48.26.el5_1.4")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-Xephyr-1.1.1-48.26.el5_1.4")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-Xnest-1.1.1-48.26.el5_1.4")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-Xorg-1.1.1-48.26.el5_1.4")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-Xvfb-1.1.1-48.26.el5_1.4")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-sdk-1.1.1-48.26.el5_1.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
