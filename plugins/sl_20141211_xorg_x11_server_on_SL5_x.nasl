#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(80017);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/12/15 16:13:13 $");

  script_cve_id("CVE-2014-8091", "CVE-2014-8092", "CVE-2014-8093", "CVE-2014-8095", "CVE-2014-8096", "CVE-2014-8097", "CVE-2014-8098", "CVE-2014-8099", "CVE-2014-8100", "CVE-2014-8101", "CVE-2014-8102");

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
"Multiple integer overflow flaws and out-of-bounds write flaws were
found in the way the X.Org server calculated memory requirements for
certain X11 core protocol and GLX extension requests. A malicious,
authenticated client could use either of these flaws to crash the
X.Org server or, potentially, execute arbitrary code with root
privileges. (CVE-2014-8092, CVE-2014-8093, CVE-2014-8098)

It was found that the X.Org server did not properly handle SUN-DES-1
(Secure RPC) authentication credentials. A malicious, unauthenticated
client could use this flaw to crash the X.Org server by submitting a
specially crafted authentication request. (CVE-2014-8091)

Multiple out-of-bounds access flaws were found in the way the X.Org
server calculated memory requirements for certain requests. A
malicious, authenticated client could use either of these flaws to
crash the X.Org server, or leak memory contents to the client.
(CVE-2014-8097)

Multiple out-of-bounds access flaws were found in the way the X.Org
server calculated memory requirements for certain requests. A
malicious, authenticated client could use either of these flaws to
crash the X.Org server. (CVE-2014-8095, CVE-2014-8096, CVE-2014-8099,
CVE-2014-8100, CVE-2014-8101, CVE-2014-8102)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1412&L=scientific-linux-errata&T=0&P=1823
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4dcd50a5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/15");
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
if (rpm_check(release:"SL5", reference:"xorg-x11-server-Xdmx-1.1.1-48.107.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-Xephyr-1.1.1-48.107.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-Xnest-1.1.1-48.107.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-Xorg-1.1.1-48.107.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-Xvfb-1.1.1-48.107.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-Xvnc-source-1.1.1-48.107.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-debuginfo-1.1.1-48.107.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-sdk-1.1.1-48.107.el5_11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
