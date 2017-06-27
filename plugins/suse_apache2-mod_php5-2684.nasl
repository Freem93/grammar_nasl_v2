#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29377);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2012/05/17 10:53:20 $");

  script_cve_id("CVE-2006-6383", "CVE-2007-0906", "CVE-2007-0907", "CVE-2007-0908", "CVE-2007-0909", "CVE-2007-0910", "CVE-2007-0911");

  script_name(english:"SuSE 10 Security Update : PHP5 (ZYPP Patch Number 2684)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes security problems also fixed in PHP 5.2.1, including
following problems :

  - Multiple buffer overflows in PHP before 5.2.1 allow
    attackers to cause a denial of service and possibly
    execute arbitrary code via unspecified vectors in the
    (1) session, (2) zip, (3) imap, and (4) sqlite
    extensions; (5) stream filters; and the (6) str_replace,
    (7) mail, (8) ibase_delete_user, (9) ibase_add_user, and
    (10) ibase_modify_user functions. (CVE-2007-0906)

  - Buffer underflow in PHP before 5.2.1 allows attackers to
    cause a denial of service via unspecified vectors
    involving the sapi_header_op function. (CVE-2007-0907)

  - The wddx extension in PHP before 5.2.1 allows remote
    attackers to obtain sensitive information via
    unspecified vectors. (CVE-2007-0908)

  - Multiple format string vulnerabilities in PHP before
    5.2.1 might allow attackers to execute arbitrary code
    via format string specifiers to (1) all of the *print
    functions on 64-bit systems, and (2) the odbc_result_all
    function. (CVE-2007-0909)

  - Unspecified vulnerability in PHP before 5.2.1 allows
    attackers to 'clobber' certain super-global variables
    via unspecified vectors. (CVE-2007-0910)

  - Off-by-one error in the str_ireplace function in PHP
    5.2.1 might allow context-dependent attackers to cause a
    denial of service (crash). (CVE-2007-0911)

  - PHP 5.2.0 and 4.4 allows local users to bypass safe_mode
    and open_basedir restrictions via a malicious path and a
    null byte before a ';' in a session_save_path argument,
    followed by an allowed path, which causes a parsing
    inconsistency in which PHP validates the allowed path
    but sets session.save_path to the malicious path. And
    another fix for open_basedir was added to stop mixing up
    its setting in a virtual host environment.
    (CVE-2006-6383)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-6383.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-0906.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-0907.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-0908.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-0909.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-0910.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-0911.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 2684.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES10", sp:0, reference:"apache2-mod_php5-5.1.2-29.25.3")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-5.1.2-29.25.3")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-bcmath-5.1.2-29.25.3")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-curl-5.1.2-29.25.3")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-dba-5.1.2-29.25.3")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-devel-5.1.2-29.25.3")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-dom-5.1.2-29.25.3")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-exif-5.1.2-29.25.3")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-fastcgi-5.1.2-29.25.3")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-ftp-5.1.2-29.25.3")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-gd-5.1.2-29.25.3")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-iconv-5.1.2-29.25.3")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-imap-5.1.2-29.25.3")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-ldap-5.1.2-29.25.3")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-mbstring-5.1.2-29.25.3")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-mhash-5.1.2-29.25.3")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-mysql-5.1.2-29.25.3")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-mysqli-5.1.2-29.25.3")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-odbc-5.1.2-29.25.3")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-pdo-5.1.2-29.25.3")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-pear-5.1.2-29.25.3")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-pgsql-5.1.2-29.25.3")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-soap-5.1.2-29.25.3")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-sysvmsg-5.1.2-29.25.3")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-wddx-5.1.2-29.25.3")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-xmlrpc-5.1.2-29.25.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
