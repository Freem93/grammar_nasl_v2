#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61346);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:57 $");

  script_cve_id("CVE-2010-3294");

  script_name(english:"Scientific Linux Security Update : php-pecl-apc on SL6.x i386/x86_64");
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
"The php-pecl-apc packages contain APC (Alternative PHP Cache), the
framework for caching and optimization of intermediate PHP code.

A cross-site scripting (XSS) flaw was found in the 'apc.php' script,
which provides a detailed analysis of the internal workings of APC and
is shipped as part of the APC extension documentation. A remote
attacker could possibly use this flaw to conduct a cross-site
scripting attack. (CVE-2010-3294)

Note: The administrative script is not deployed upon package
installation. It must manually be copied to the web root (the default
is '/var/www/html/', for example).

In addition, the php-pecl-apc packages have been upgraded to upstream
version 3.1.9, which provides a number of bug fixes and enhancements
over the previous version.

All users of php-pecl-apc are advised to upgrade to these updated
packages, which fix these issues and add these enhancements. If the
'apc.php' script was previously deployed in the web root, it must
manually be re-deployed to replace the vulnerable version to resolve
this issue."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1207&L=scientific-linux-errata&T=0&P=3222
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1e1d92ac"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected php-pecl-apc, php-pecl-apc-debuginfo and / or
php-pecl-apc-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"php-pecl-apc-3.1.9-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"php-pecl-apc-debuginfo-3.1.9-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"php-pecl-apc-devel-3.1.9-2.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
