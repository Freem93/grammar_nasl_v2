#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29376);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2012/05/17 10:53:20 $");

  script_cve_id("CVE-2006-5465");

  script_name(english:"SuSE 10 Security Update : PHP (ZYPP Patch Number 2236)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the following security problems in the PHP scripting
language :

  - Various buffer overflows in
    htmlentities/htmlspecialchars internal routines could be
    used to crash the PHP interpreter or potentially execute
    code, depending on the PHP application used.
    (CVE-2006-5465)

  - A missing open_basedir check inside chdir() function was
    added.

  - A tempnam() openbasedir bypass was fixed.

  - A possible buffer overflow in stream_socket_client()
    when using 'bindto' + IPv6 was fixed.

  - Do not build php5 with --enable-sigchld."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-5465.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 2236.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/07");
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
if (rpm_check(release:"SLES10", sp:0, reference:"apache2-mod_php5-5.1.2-29.22")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-5.1.2-29.22")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-bcmath-5.1.2-29.22")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-curl-5.1.2-29.22")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-dba-5.1.2-29.22")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-devel-5.1.2-29.22")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-dom-5.1.2-29.22")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-exif-5.1.2-29.22")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-fastcgi-5.1.2-29.22")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-ftp-5.1.2-29.22")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-gd-5.1.2-29.22")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-iconv-5.1.2-29.22")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-imap-5.1.2-29.22")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-ldap-5.1.2-29.22")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-mbstring-5.1.2-29.22")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-mysql-5.1.2-29.22")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-mysqli-5.1.2-29.22")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-pdo-5.1.2-29.22")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-pear-5.1.2-29.22")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-pgsql-5.1.2-29.22")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-soap-5.1.2-29.22")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-wddx-5.1.2-29.22")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"php5-xmlrpc-5.1.2-29.22")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
