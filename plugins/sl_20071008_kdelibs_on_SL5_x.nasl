#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60263);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:22:12 $");

  script_cve_id("CVE-2007-0242", "CVE-2007-0537", "CVE-2007-1308", "CVE-2007-1564", "CVE-2007-3820", "CVE-2007-4224");

  script_name(english:"Scientific Linux Security Update : kdelibs on SL5.x, SL4.x i386/x86_64");
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
"Two cross-site-scripting flaws were found in the way Konqueror
processes certain HTML content. This could result in a malicious
attacker presenting misleading content to an unsuspecting user.
(CVE-2007-0242, CVE-2007-0537)

A flaw was found in KDE JavaScript implementation. A web page
containing malicious JavaScript code could cause Konqueror to crash.
(CVE-2007-1308)

A flaw was found in the way Konqueror handled certain FTP PASV
commands. A malicious FTP server could use this flaw to perform a
rudimentary port-scan of machines behind a user's firewall.
(CVE-2007-1564)

Two Konqueror address spoofing flaws have been discovered. It was
possible for a malicious website to cause the Konqueror address bar to
display information which could trick a user into believing they are
at a different website than they actually are. (CVE-2007-3820,
CVE-2007-4224)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0710&L=scientific-linux-errata&T=0&P=778
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?838c29bc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected kdelibs, kdelibs-apidocs and / or kdelibs-devel
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(59, 79, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/08");
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
if (rpm_check(release:"SL4", reference:"kdelibs-3.3.1-9.el4")) flag++;
if (rpm_check(release:"SL4", reference:"kdelibs-devel-3.3.1-9.el4")) flag++;

if (rpm_check(release:"SL5", reference:"kdelibs-3.5.4-13.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kdelibs-apidocs-3.5.4-13.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kdelibs-devel-3.5.4-13.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
