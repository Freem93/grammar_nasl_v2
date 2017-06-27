#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41143);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/21 20:21:21 $");

  script_cve_id("CVE-2007-2727", "CVE-2007-3472", "CVE-2007-3475", "CVE-2007-3476", "CVE-2007-3477", "CVE-2007-3478", "CVE-2007-3799");

  script_name(english:"SuSE9 Security Update : PHP4 (YOU Patch Number 11666)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 9 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes multiple bugs in PHP :

  - Predictable generaton of an initialization vector (IV)
    in the mcrypt extension

  - Additional cookie attributes could be injected via a
    session ID.

  - Specially crafted files could cause integer overflows in
    gd and leverage them to at least crash gd based
    applications.

This update covers CVE IDs CVE-2007-2727, CVE-2007-3472,
CVE-2007-3475, CVE-2007-3476 CVE-2007-3477, CVE-2007-3478 and
CVE-2007-3799."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-2727.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-3472.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-3475.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-3476.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-3477.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-3478.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-3799.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply YOU patch number 11666.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(20, 189, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 9 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SUSE9", reference:"apache-mod_php4-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"apache2-mod_php4-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"mod_php4-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"mod_php4-apache2-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"mod_php4-core-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"mod_php4-servlet-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-bcmath-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-bz2-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-calendar-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-ctype-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-curl-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-dba-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-dbase-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-devel-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-domxml-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-exif-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-fastcgi-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-filepro-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-ftp-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-gd-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-gettext-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-gmp-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-imap-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-ldap-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-mbstring-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-mcal-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-mcrypt-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-mhash-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-mime_magic-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-mysql-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-pear-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-pgsql-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-qtdom-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-readline-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-recode-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-servlet-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-session-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-shmop-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-snmp-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-sockets-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-sysvsem-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-sysvshm-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-unixODBC-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-wddx-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-xslt-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-yp-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", reference:"php4-zlib-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"php4-iconv-4.3.4-43.82")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"php4-swf-4.3.4-43.82")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
