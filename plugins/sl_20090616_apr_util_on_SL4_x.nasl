#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60597);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/14 20:33:25 $");

  script_cve_id("CVE-2009-0023", "CVE-2009-1955", "CVE-2009-1956");

  script_name(english:"Scientific Linux Security Update : apr-util on SL4.x, SL5.x i386/x86_64");
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
"An off-by-one overflow flaw was found in the way apr-util processed a
variable list of arguments. An attacker could provide a specially
crafted string as input for the formatted output conversion routine,
which could, on big-endian platforms, potentially lead to the
disclosure of sensitive information or a denial of service
(application crash). (CVE-2009-1956)

A denial of service flaw was found in the apr-util Extensible Markup
Language (XML) parser. A remote attacker could create a specially
crafted XML document that would cause excessive memory consumption
when processed by the XML decoding engine. (CVE-2009-1955)

A heap-based underwrite flaw was found in the way apr-util created
compiled forms of particular search patterns. An attacker could
formulate a specially crafted search keyword, that would overwrite
arbitrary heap memory locations when processed by the pattern
preparation engine. (CVE-2009-0023)

Applications using the Apache Portable Runtime library, such as httpd,
must be restarted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0906&L=scientific-linux-errata&T=0&P=1194
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?95ea0716"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected apr-util, apr-util-devel and / or apr-util-docs
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/16");
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
if (rpm_check(release:"SL4", reference:"apr-util-0.9.4-22.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"apr-util-devel-0.9.4-22.el4_8.1")) flag++;

if (rpm_check(release:"SL5", reference:"apr-util-1.2.7-7.el5_3.1")) flag++;
if (rpm_check(release:"SL5", reference:"apr-util-devel-1.2.7-7.el5_3.1")) flag++;
if (rpm_check(release:"SL5", reference:"apr-util-docs-1.2.7-7.el5_3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
