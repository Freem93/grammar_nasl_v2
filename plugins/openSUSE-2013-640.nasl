#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-640.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75112);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/20 15:05:36 $");

  script_cve_id("CVE-2009-5031", "CVE-2012-2751", "CVE-2012-4528", "CVE-2013-1915", "CVE-2013-2765");
  script_osvdb_id(83178, 86408, 91948, 93687);

  script_name(english:"openSUSE Security Update : apache2-mod_security2 (openSUSE-SU-2013:1336-1)");
  script_summary(english:"Check for the openSUSE-2013-640 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - complete overhaul of this package, with update to 2.7.5.

  - ruleset update to 2.2.8-0-g0f07cbb. 

  - new configuration framework private to mod_security2:
    /etc/apache2/conf.d/mod_security2.conf loads
    /usr/share/apache2-mod_security2/rules/modsecurity_crs_1
    0_setup.conf, then /etc/apache2/mod_security2.d/*.conf ,
    as set up based on advice in
    /etc/apache2/conf.d/mod_security2.conf Your
    configuration starting point is
    /etc/apache2/conf.d/mod_security2.conf

  - !!! Please note that mod_unique_id is needed for
    mod_security2 to run!

  - modsecurity-apache_2.7.5-build_fix_pcre.diff changes
    erroneaous linker parameter, preventing rpath in shared
    object.

  - fixes contained for the following bugs :

  - CVE-2009-5031, CVE-2012-2751 [bnc#768293] request
    parameter handling

  - [bnc#768293] multi-part bypass, minor threat

  - CVE-2013-1915 [bnc#813190] XML external entity
    vulnerability

  - CVE-2012-4528 [bnc#789393] rule bypass

  - CVE-2013-2765 [bnc#822664] NULL pointer dereference
    crash

  - new from 2.5.9 to 2.7.5, only major changes :

  - GPLv2 replaced by Apache License v2

  - rules are not part of the source tarball any longer, but
    maintaned upstream externally, and included in this
    package.

  - documentation was externalized to a wiki. Package
    contains the FAQ and the reference manual in html form.

  - renamed the term 'Encryption' in directives that
    actually refer to hashes. See CHANGES file for more
    details.

  - new directive SecXmlExternalEntity, default off

  - byte conversion issues on s390x when logging fixed.

  - many small issues fixed that were discovered by a
    Coverity scanner

  - updated reference manual

  - wrong time calculation when logging for some timezones
    fixed.

  - replaced time-measuring mechanism with finer granularity
    for measured request/answer phases. (Stopwatch remains
    for compat.)

  - cookie parser memory leak fix

  - parsing of quoted strings in multipart
    Content-Disposition headers fixed.

  - SDBM deadlock fix

  - @rsub memory leak fix

  - cookie separator code improvements

  - build failure fixes

  - compile time option --enable-htaccess-config (set)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-08/msg00025.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=768293"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=789393"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=813190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=822664"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache2-mod_security2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-mod_security2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-mod_security2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-mod_security2-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"apache2-mod_security2-2.7.5-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"apache2-mod_security2-debuginfo-2.7.5-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"apache2-mod_security2-debugsource-2.7.5-14.4.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2-mod_security2 / apache2-mod_security2-debuginfo / etc");
}
