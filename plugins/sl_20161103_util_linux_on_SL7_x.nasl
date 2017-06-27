#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(95864);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/04/18 13:37:17 $");

  script_cve_id("CVE-2016-5011");

  script_name(english:"Scientific Linux Security Update : util-linux on SL7.x x86_64");
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
"Security Fix(es) :

  - It was found that util-linux's libblkid library did not
    properly handle Extended Boot Record (EBR) partitions
    when reading MS-DOS partition tables. An attacker with
    physical USB access to a protected machine could insert
    a storage device with a specially crafted partition
    table that could, for example, trigger an infinite loop
    in systemd-udevd, resulting in a denial of service on
    that machine. (CVE-2016-5011)

Additional Changes :"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1612&L=scientific-linux-errata&F=&S=&P=3139
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?246b2d24"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libblkid-2.23.2-33.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libblkid-devel-2.23.2-33.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libmount-2.23.2-33.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libmount-devel-2.23.2-33.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libuuid-2.23.2-33.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libuuid-devel-2.23.2-33.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"util-linux-2.23.2-33.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"util-linux-debuginfo-2.23.2-33.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"uuidd-2.23.2-33.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
