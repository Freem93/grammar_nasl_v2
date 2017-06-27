#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(69945);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/11/06 11:54:17 $");

  script_cve_id("CVE-2013-1718", "CVE-2013-1722", "CVE-2013-1725", "CVE-2013-1730", "CVE-2013-1732", "CVE-2013-1735", "CVE-2013-1736", "CVE-2013-1737");

  script_name(english:"Scientific Linux Security Update : firefox on SL5.x, SL6.x i386/srpm/x86_64");
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
running Firefox. (CVE-2013-1718, CVE-2013-1722, CVE-2013-1725,
CVE-2013-1730, CVE-2013-1732, CVE-2013-1735, CVE-2013-1736)

A flaw was found in the way Firefox handled certain DOM JavaScript
objects. An attacker could use this flaw to make JavaScript client or
add- on code make incorrect, security sensitive decisions.
(CVE-2013-1737)

After installing the update, Firefox must be restarted for the changes
to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1309&L=scientific-linux-errata&T=0&P=919
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?697c7c12"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"firefox-17.0.9-1.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"firefox-debuginfo-17.0.9-1.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"firefox-debuginfo-17.0.9-1.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-17.0.9-1.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-debuginfo-17.0.9-1.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-debuginfo-17.0.9-1.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-devel-17.0.9-1.el5_9")) flag++;

if (rpm_check(release:"SL6", reference:"firefox-17.0.9-1.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"firefox-debuginfo-17.0.9-1.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"firefox-debuginfo-17.0.9-1.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"xulrunner-17.0.9-1.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"xulrunner-debuginfo-17.0.9-1.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"xulrunner-debuginfo-17.0.9-1.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"xulrunner-devel-17.0.9-1.el6_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
