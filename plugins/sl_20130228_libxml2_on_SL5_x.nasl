#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(64964);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/01/26 05:42:54 $");

  script_cve_id("CVE-2013-0338");

  script_name(english:"Scientific Linux Security Update : libxml2 on SL5.x, SL6.x i386/x86_64");
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
"A denial of service flaw was found in the way libxml2 performed string
substitutions when entity values for entity references replacement was
enabled. A remote attacker could provide a specially crafted XML file
that, when processed by an application linked against libxml2, would
lead to excessive CPU consumption. (CVE-2013-0338)

The desktop must be restarted (log out, then log back in) for this
update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1302&L=scientific-linux-errata&T=0&P=5918
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?34538460"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"libxml2-2.6.26-2.1.21.el5_9.1")) flag++;
if (rpm_check(release:"SL5", reference:"libxml2-debuginfo-2.6.26-2.1.21.el5_9.1")) flag++;
if (rpm_check(release:"SL5", reference:"libxml2-devel-2.6.26-2.1.21.el5_9.1")) flag++;
if (rpm_check(release:"SL5", reference:"libxml2-python-2.6.26-2.1.21.el5_9.1")) flag++;

if (rpm_check(release:"SL6", reference:"libxml2-2.7.6-12.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"libxml2-debuginfo-2.7.6-12.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"libxml2-devel-2.7.6-12.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"libxml2-python-2.7.6-12.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"libxml2-static-2.7.6-12.el6_4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
