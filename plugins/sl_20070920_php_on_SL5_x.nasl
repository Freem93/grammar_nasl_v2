#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60255);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:22:12 $");

  script_cve_id("CVE-2007-2756", "CVE-2007-2872", "CVE-2007-3799", "CVE-2007-3996", "CVE-2007-3998", "CVE-2007-4658", "CVE-2007-4670");

  script_name(english:"Scientific Linux Security Update : php on SL5.x, SL4.x i386/x86_64");
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
"Various integer overflow flaws were found in the PHP gd extension. A
script that could be forced to resize images from an untrusted source
could possibly allow a remote attacker to execute arbitrary code as
the apache user. (CVE-2007-3996)

An integer overflow flaw was found in the PHP chunk_split function. If
a remote attacker was able to pass arbitrary data to the third
argument of chunk_split they could possibly execute arbitrary code as
the apache user. Note that it is unusual for a PHP script to use the
chunk_script function with a user-supplied third argument.
(CVE-2007-2872)

A previous security update introduced a bug into PHP session cookie
handling. This could allow an attacker to stop a victim from viewing a
vulnerable website if the victim has first visited a malicious web
page under the control of the attacker, and that page can set a cookie
for the vulnerable website. (CVE-2007-4670)

A flaw was found in the PHP money_format function. If a remote
attacker was able to pass arbitrary data to the money_format function
this could possibly result in an information leak or denial of
service. Note that is is unusual for a PHP script to pass
user-supplied data to the money_format function. (CVE-2007-4658)

A flaw was found in the PHP wordwrap function. If a remote attacker
was able to pass arbitrary data to the wordwrap function this could
possibly result in a denial of service. (CVE-2007-3998)

A bug was found in PHP session cookie handling. This could allow an
attacker to create a cross-site cookie insertion attack if a victim
follows an untrusted carefully-crafted URL. (CVE-2007-3799)

An infinite-loop flaw was discovered in the PHP gd extension. A script
that could be forced to process PNG images from an untrusted source
could allow a remote attacker to cause a denial of service.
(CVE-2007-2756)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0709&L=scientific-linux-errata&T=0&P=1777
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?99f422b6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(20, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/20");
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
if (rpm_check(release:"SL4", reference:"php-4.3.9-3.22.9")) flag++;
if (rpm_check(release:"SL4", reference:"php-devel-4.3.9-3.22.9")) flag++;
if (rpm_check(release:"SL4", reference:"php-domxml-4.3.9-3.22.9")) flag++;
if (rpm_check(release:"SL4", reference:"php-gd-4.3.9-3.22.9")) flag++;
if (rpm_check(release:"SL4", reference:"php-imap-4.3.9-3.22.9")) flag++;
if (rpm_check(release:"SL4", reference:"php-ldap-4.3.9-3.22.9")) flag++;
if (rpm_check(release:"SL4", reference:"php-mbstring-4.3.9-3.22.9")) flag++;
if (rpm_check(release:"SL4", reference:"php-mysql-4.3.9-3.22.9")) flag++;
if (rpm_check(release:"SL4", reference:"php-ncurses-4.3.9-3.22.9")) flag++;
if (rpm_check(release:"SL4", reference:"php-odbc-4.3.9-3.22.9")) flag++;
if (rpm_check(release:"SL4", reference:"php-pear-4.3.9-3.22.9")) flag++;
if (rpm_check(release:"SL4", reference:"php-pgsql-4.3.9-3.22.9")) flag++;
if (rpm_check(release:"SL4", reference:"php-snmp-4.3.9-3.22.9")) flag++;
if (rpm_check(release:"SL4", reference:"php-xmlrpc-4.3.9-3.22.9")) flag++;

if (rpm_check(release:"SL5", reference:"php-5.1.6-15.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php-bcmath-5.1.6-15.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php-cli-5.1.6-15.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php-common-5.1.6-15.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php-dba-5.1.6-15.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php-devel-5.1.6-15.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php-gd-5.1.6-15.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php-imap-5.1.6-15.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php-ldap-5.1.6-15.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php-mbstring-5.1.6-15.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php-mysql-5.1.6-15.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php-ncurses-5.1.6-15.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php-odbc-5.1.6-15.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php-pdo-5.1.6-15.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php-pgsql-5.1.6-15.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php-snmp-5.1.6-15.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php-soap-5.1.6-15.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php-xml-5.1.6-15.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php-xmlrpc-5.1.6-15.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
