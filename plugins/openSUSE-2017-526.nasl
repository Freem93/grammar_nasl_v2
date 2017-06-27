#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-526.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(99752);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/01 13:40:22 $");

  script_cve_id("CVE-2016-10324", "CVE-2016-10325", "CVE-2016-10326", "CVE-2017-7853");

  script_name(english:"openSUSE Security Update : libosip2 (openSUSE-2017-526)");
  script_summary(english:"Check for the openSUSE-2017-526 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libosip2 fixes the following issues :

Changes in libosip2 :

  - CVE-2017-7853: In libosip2 in GNU 5.0.0, a malformed SIP
    message can lead to a heap buffer overflow in the
    msg_osip_body_parse() function defined in
    osipparser2/osip_message_parse.c, resulting in a remote
    DoS. (boo#1034570)

  - CVE-2016-10326: In libosip2 in GNU oSIP 4.1.0, a
    malformed SIP message can lead to a heap buffer overflow
    in the osip_body_to_str() function defined in
    osipparser2/osip_body.c, resulting in a remote DoS.
    (boo#1034571)

  - CVE-2016-10325: In libosip2 in GNU oSIP 4.1.0, a
    malformed SIP message can lead to a heap buffer overflow
    in the _osip_message_to_str() function defined in
    osipparser2/osip_message_to_str.c, resulting in a remote
    DoS. (boo#1034572)

  - CVE-2016-10324: In libosip2 in GNU oSIP 4.1.0, a
    malformed SIP message can lead to a heap buffer overflow
    in the osip_clrncpy() function defined in
    osipparser2/osip_port.c. (boo#1034574)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034570"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034571"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034572"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034574"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libosip2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libosip2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libosip2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libosip2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libosip2-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"libosip2-4.1.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libosip2-debuginfo-4.1.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libosip2-debugsource-4.1.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libosip2-devel-4.1.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libosip2-4.1.0-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libosip2-debuginfo-4.1.0-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libosip2-debugsource-4.1.0-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libosip2-devel-4.1.0-5.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libosip2 / libosip2-debuginfo / libosip2-debugsource / etc");
}
