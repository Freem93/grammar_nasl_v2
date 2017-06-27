#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60198);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:52 $");

  script_cve_id("CVE-2006-3619");

  script_name(english:"Scientific Linux Security Update : gcc on SL3.x i386/x86_64");
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
"J&uuml;rgen Weigert discovered a directory traversal flaw in fastjar.
An attacker could create a malicious JAR file which, if unpacked using
fastjar, could write to any files the victim had write access to.
(CVE-2006-3619)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0706&L=scientific-linux-errata&T=0&P=2591
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?77e7300c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/11");
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
if (rpm_check(release:"SL3", reference:"cpp-3.2.3-59")) flag++;
if (rpm_check(release:"SL3", reference:"gcc-3.2.3-59")) flag++;
if (rpm_check(release:"SL3", reference:"gcc-c++-3.2.3-59")) flag++;
if (rpm_check(release:"SL3", reference:"gcc-g77-3.2.3-59")) flag++;
if (rpm_check(release:"SL3", reference:"gcc-gnat-3.2.3-59")) flag++;
if (rpm_check(release:"SL3", reference:"gcc-java-3.2.3-59")) flag++;
if (rpm_check(release:"SL3", reference:"gcc-objc-3.2.3-59")) flag++;
if (rpm_check(release:"SL3", reference:"libf2c-3.2.3-59")) flag++;
if (rpm_check(release:"SL3", reference:"libgcc-3.2.3-59")) flag++;
if (rpm_check(release:"SL3", reference:"libgcj-3.2.3-59")) flag++;
if (rpm_check(release:"SL3", reference:"libgcj-devel-3.2.3-59")) flag++;
if (rpm_check(release:"SL3", reference:"libgnat-3.2.3-59")) flag++;
if (rpm_check(release:"SL3", reference:"libobjc-3.2.3-59")) flag++;
if (rpm_check(release:"SL3", reference:"libstdc++-3.2.3-59")) flag++;
if (rpm_check(release:"SL3", reference:"libstdc++-devel-3.2.3-59")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
