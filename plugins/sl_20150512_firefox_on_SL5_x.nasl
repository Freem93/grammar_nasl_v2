#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(83450);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2015/07/12 04:39:12 $");

  script_cve_id("CVE-2015-0797", "CVE-2015-2708", "CVE-2015-2710", "CVE-2015-2713", "CVE-2015-2716");

  script_name(english:"Scientific Linux Security Update : firefox on SL5.x, SL6.x, SL7.x i386/x86_64");
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
"Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2015-2708, CVE-2015-0797, CVE-2015-2710,
CVE-2015-2713)

A heap-based buffer overflow flaw was found in the way Firefox
processed compressed XML data. An attacker could create specially
crafted compressed XML content that, when processed by Firefox, could
cause it to crash or execute arbitrary code with the privileges of the
user running Firefox. (CVE-2015-2716)

After installing the update, Firefox must be restarted for the changes
to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1505&L=scientific-linux-errata&T=0&P=1996
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fab29fc3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox and / or firefox-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"firefox-38.0-4.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"firefox-debuginfo-38.0-4.el5_11")) flag++;

if (rpm_check(release:"SL6", reference:"firefox-38.0-4.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"firefox-debuginfo-38.0-4.el6_6")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"firefox-38.0-3.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"firefox-debuginfo-38.0-3.el7_1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
