#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(66017);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/05/01 10:51:15 $");

  script_cve_id("CVE-2013-1926", "CVE-2013-1927");

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
"It was discovered that the IcedTea-Web plug-in incorrectly used the
same class loader instance for applets with the same value of the
codebase attribute, even when they originated from different domains.
A malicious applet could use this flaw to gain information about and
possibly manipulate applets from different domains currently running
in the browser. (CVE-2013-1926)

The IcedTea-Web plug-in did not properly check the format of the
downloaded Java Archive (JAR) files. This could cause the plug-in to
execute code hidden in a file in a different format, possibly allowing
attackers to execute code in the context of web sites that allow
uploads of specific file types, known as a GIFAR attack.
(CVE-2013-1927)

This erratum also upgrades IcedTea-Web to version 1.2.3.

Web browsers using the IcedTea-Web browser plug-in must be restarted
for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1304&L=scientific-linux-errata&T=0&P=1839
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f493f85f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected icedtea-web, icedtea-web-debuginfo and / or
icedtea-web-javadoc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/18");
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
if (rpm_check(release:"SL6", reference:"icedtea-web-1.2.3-2.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"icedtea-web-debuginfo-1.2.3-2.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"icedtea-web-javadoc-1.2.3-2.el6_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
