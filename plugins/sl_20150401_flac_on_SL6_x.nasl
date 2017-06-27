#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(82521);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/04/02 13:36:27 $");

  script_cve_id("CVE-2014-8962", "CVE-2014-9028");

  script_name(english:"Scientific Linux Security Update : flac on SL6.x, SL7.x i386/x86_64");
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
"A buffer overflow flaw was found in the way flac decoded FLAC audio
files. An attacker could create a specially crafted FLAC audio file
that could cause an application using the flac library to crash or
execute arbitrary code when the file was read. (CVE-2014-9028)

A buffer over-read flaw was found in the way flac processed certain
ID3v2 metadata. An attacker could create a specially crafted FLAC
audio file that could cause an application using the flac library to
crash when the file was read. (CVE-2014-8962)

After installing the update, all applications linked against the flac
library must be restarted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1504&L=scientific-linux-errata&T=0&P=76
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?935f212c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/02");
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
if (rpm_check(release:"SL6", reference:"flac-1.2.1-7.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"flac-debuginfo-1.2.1-7.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"flac-devel-1.2.1-7.el6_6")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"flac-1.3.0-5.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"flac-debuginfo-1.3.0-5.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"flac-devel-1.3.0-5.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"flac-libs-1.3.0-5.el7_1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
