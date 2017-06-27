#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60350);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2007-3389", "CVE-2007-3390", "CVE-2007-3391", "CVE-2007-3392", "CVE-2007-3393", "CVE-2007-6111", "CVE-2007-6112", "CVE-2007-6113", "CVE-2007-6114", "CVE-2007-6115", "CVE-2007-6116", "CVE-2007-6117", "CVE-2007-6118", "CVE-2007-6119", "CVE-2007-6120", "CVE-2007-6121", "CVE-2007-6438", "CVE-2007-6439", "CVE-2007-6441", "CVE-2007-6450", "CVE-2007-6451");

  script_name(english:"Scientific Linux Security Update : wireshark on SL3.x, SL4.x, SL5.x i386/x86_64");
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
"Several flaws were found in Wireshark. Wireshark could crash or
possibly execute arbitrary code as the user running Wireshark if it
read a malformed packet off the network. (CVE-2007-6112,
CVE-2007-6114, CVE-2007-6115, CVE-2007-6117)

Several denial of service bugs were found in Wireshark. Wireshark
could crash or stop responding if it read a malformed packet off the
network. (CVE-2007-3389, CVE-2007-3390, CVE-2007-3391, CVE-2007-3392,
CVE-2007-3392, CVE-2007-3393, CVE-2007-6111, CVE-2007-6113,
CVE-2007-6116, CVE-2007-6118, CVE-2007-6119, CVE-2007-6120,
CVE-2007-6121, CVE-2007-6438, CVE-2007-6439, CVE-2007-6441,
CVE-2007-6450, CVE-2007-6451)

As well, Wireshark switched from using net-snmp to libsmi, which is
included in this errata."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0801&L=scientific-linux-errata&T=0&P=1833
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4226f5b3"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 119, 189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/21");
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
if (rpm_check(release:"SL3", reference:"libsmi-0.4.5-3.el3")) flag++;
if (rpm_check(release:"SL3", reference:"libsmi-devel-0.4.5-3.el3")) flag++;
if (rpm_check(release:"SL3", reference:"wireshark-0.99.7-EL3.1")) flag++;
if (rpm_check(release:"SL3", reference:"wireshark-gnome-0.99.7-EL3.1")) flag++;

if (rpm_check(release:"SL4", cpu:"i386", reference:"libsmi-0.4.5-2.el4_6")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"libsmi-0.4.5-2")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"libsmi-devel-0.4.5-2.el4_6")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"libsmi-devel-0.4.5-2")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"wireshark-0.99.7-1.el4_6")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"wireshark-0.99.7-1")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"wireshark-gnome-0.99.7-1.el4_6")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"wireshark-gnome-0.99.7-1")) flag++;

if (rpm_check(release:"SL5", reference:"libsmi-0.4.5-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libsmi-devel-0.4.5-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"wireshark-0.99.7-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"wireshark-gnome-0.99.7-1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
