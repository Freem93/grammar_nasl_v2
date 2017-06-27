#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(29780);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/22 20:32:45 $");

  script_cve_id("CVE-2005-4872", "CVE-2006-7227", "CVE-2006-7228", "CVE-2006-7230", "CVE-2007-1659", "CVE-2007-1660", "CVE-2007-3996", "CVE-2007-3998", "CVE-2007-4658", "CVE-2007-4661", "CVE-2007-4782", "CVE-2007-4784", "CVE-2007-4825", "CVE-2007-4840", "CVE-2007-5898");

  script_name(english:"SuSE 10 Security Update : PHP5 (ZYPP Patch Number 4808)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes multiple bugs in php :

  - use system pcre library to fix several pcre
    vulnerabilities. (CVE-2007-1659 / CVE-2006-7230 /
    CVE-2007-1660 / CVE-2006-7227 / CVE-2005-4872 /
    CVE-2006-7228)

  - Flaws in processing multi byte sequences in
    htmlentities/htmlspecialchars. (CVE-2007-5898)

  - overly long arguments to the dl() function could crash
    php. (CVE-2007-4825)

  - overy long arguments to the glob() function could crash
    php. (CVE-2007-4782)

  - overly long arguments to some iconv functions could
    crash php. (CVE-2007-4840)

  - overy long arguments to the setlocale() function could
    crash php. (CVE-2007-4784)

  - the wordwrap-Function could cause a floating point
    exception. (CVE-2007-3998)

  - overy long arguments to the fnmatch() function could
    crash php. (CVE-2007-4782)

  - incorrect size calculation in the chunk_split function
    could lead to a buffer overflow. (CVE-2007-4661)

  - Flaws in the GD extension could lead to integer
    overflows. (CVE-2007-3996)

  - The money_format function contained format string flaws.
    (CVE-2007-4658)

  - Data for some time zones has been updated"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2005-4872.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-7227.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-7228.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-7230.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-1659.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-1660.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-3996.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-3998.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-4658.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-4661.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-4782.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-4784.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-4825.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-4840.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-5898.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 4808.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(20, 22, 94, 119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLES10", sp:1, reference:"apache2-mod_php5-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-bcmath-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-bz2-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-calendar-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-ctype-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-curl-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-dba-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-dbase-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-devel-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-dom-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-exif-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-fastcgi-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-filepro-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-ftp-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-gd-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-gettext-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-gmp-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-iconv-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-imap-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-ldap-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-mbstring-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-mcrypt-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-mhash-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-mysql-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-mysqli-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-ncurses-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-odbc-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-openssl-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-pcntl-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-pdo-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-pear-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-pgsql-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-posix-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-pspell-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-shmop-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-snmp-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-soap-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-sockets-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-sqlite-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-suhosin-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-sysvmsg-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-sysvsem-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-sysvshm-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-tokenizer-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-wddx-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-xmlreader-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-xmlrpc-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-xsl-5.1.2-29.50")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"php5-zlib-5.1.2-29.50")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
