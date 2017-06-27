#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61171);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/02/07 11:46:01 $");

  script_cve_id("CVE-2011-3377");

  script_name(english:"Scientific Linux Security Update : icedtea-web on SL6.x i386/x86_64");
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
"The IcedTea-Web project provides a Java web browser plug-in and an
implementation of Java Web Start, which is based on the Netx project.
It also contains a configuration tool for managing deployment settings
for the plug-in and Web Start implementations.

A flaw was found in the same-origin policy implementation in the
IcedTea-Web browser plug-in. A malicious Java applet could use this
flaw to open network connections to hosts other than the originating
host, violating the same-origin policy. (CVE-2011-3377)

All IcedTea-Web users should upgrade to these updated packages, which
upgrade IcedTea-Web to version 1.0.6 to correct this issue. Web
browsers using the IcedTea-Web browser plug-in must be restarted for
this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1111&L=scientific-linux-errata&T=0&P=1615
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4014c815"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected icedtea-web, icedtea-web-debuginfo and / or
icedtea-web-javadoc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"icedtea-web-1.0.6-1.el6_1")) flag++;
if (rpm_check(release:"SL6", reference:"icedtea-web-debuginfo-1.0.6-1.el6_1")) flag++;
if (rpm_check(release:"SL6", reference:"icedtea-web-javadoc-1.0.6-1.el6_1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
