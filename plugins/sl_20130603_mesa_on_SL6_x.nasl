#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(66779);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/06/18 10:54:29 $");

  script_cve_id("CVE-2013-1872", "CVE-2013-1993");

  script_name(english:"Scientific Linux Security Update : mesa on SL6.x i386/x86_64");
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
"An out-of-bounds access flaw was found in Mesa. If an application
using Mesa exposed the Mesa API to untrusted inputs (Mozilla Firefox
does this), an attacker could cause the application to crash or,
potentially, execute arbitrary code with the privileges of the user
running the application. (CVE-2013-1872)

It was found that Mesa did not correctly validate messages from the X
server. A malicious X server could cause an application using Mesa to
crash or, potentially, execute arbitrary code with the privileges of
the user running the application. (CVE-2013-1993)

All running applications linked against Mesa must be restarted for
this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1306&L=scientific-linux-errata&T=0&P=466
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e073909b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/04");
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
if (rpm_check(release:"SL6", reference:"glx-utils-9.0-0.8.el6_4.3")) flag++;
if (rpm_check(release:"SL6", reference:"mesa-debuginfo-9.0-0.8.el6_4.3")) flag++;
if (rpm_check(release:"SL6", reference:"mesa-demos-9.0-0.8.el6_4.3")) flag++;
if (rpm_check(release:"SL6", reference:"mesa-dri-drivers-9.0-0.8.el6_4.3")) flag++;
if (rpm_check(release:"SL6", reference:"mesa-dri-filesystem-9.0-0.8.el6_4.3")) flag++;
if (rpm_check(release:"SL6", reference:"mesa-libGL-9.0-0.8.el6_4.3")) flag++;
if (rpm_check(release:"SL6", reference:"mesa-libGL-devel-9.0-0.8.el6_4.3")) flag++;
if (rpm_check(release:"SL6", reference:"mesa-libGLU-9.0-0.8.el6_4.3")) flag++;
if (rpm_check(release:"SL6", reference:"mesa-libGLU-devel-9.0-0.8.el6_4.3")) flag++;
if (rpm_check(release:"SL6", reference:"mesa-libOSMesa-9.0-0.8.el6_4.3")) flag++;
if (rpm_check(release:"SL6", reference:"mesa-libOSMesa-devel-9.0-0.8.el6_4.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
