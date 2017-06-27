#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-401.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74989);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:13 $");

  script_cve_id("CVE-2013-1416");
  script_bugtraq_id(59261);
  script_osvdb_id(92540);

  script_name(english:"openSUSE Security Update : krb5 (openSUSE-SU-2013:0904-1)");
  script_summary(english:"Check for the openSUSE-2013-401 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - fix prep_reprocess_req NULL pointer deref CVE-2013-1416
    (bnc#816413)
    bug-816413-CVE-2013-1416-prep_reprocess_req-NULL-ptr-der
    ef.dif"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-05/msg00011.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-06/msg00041.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=816413"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected krb5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-mini-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-mini-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-plugin-kdb-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-plugin-kdb-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-plugin-preauth-pkinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-plugin-preauth-pkinit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/22");
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
if (release !~ "^(SUSE12\.1|SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1 / 12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"krb5-1.9.1-24.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"krb5-client-1.9.1-24.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"krb5-client-debuginfo-1.9.1-24.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"krb5-debuginfo-1.9.1-24.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"krb5-debugsource-1.9.1-24.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"krb5-devel-1.9.1-24.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"krb5-plugin-kdb-ldap-1.9.1-24.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"krb5-plugin-kdb-ldap-debuginfo-1.9.1-24.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"krb5-plugin-preauth-pkinit-1.9.1-24.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"krb5-plugin-preauth-pkinit-debuginfo-1.9.1-24.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"krb5-server-1.9.1-24.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"krb5-server-debuginfo-1.9.1-24.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"krb5-32bit-1.9.1-24.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"krb5-debuginfo-32bit-1.9.1-24.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"krb5-devel-32bit-1.9.1-24.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"krb5-1.10.2-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"krb5-client-1.10.2-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"krb5-client-debuginfo-1.10.2-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"krb5-debuginfo-1.10.2-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"krb5-debugsource-1.10.2-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"krb5-devel-1.10.2-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"krb5-mini-1.10.2-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"krb5-mini-debuginfo-1.10.2-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"krb5-mini-debugsource-1.10.2-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"krb5-mini-devel-1.10.2-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"krb5-plugin-kdb-ldap-1.10.2-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"krb5-plugin-kdb-ldap-debuginfo-1.10.2-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"krb5-plugin-preauth-pkinit-1.10.2-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"krb5-plugin-preauth-pkinit-debuginfo-1.10.2-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"krb5-server-1.10.2-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"krb5-server-debuginfo-1.10.2-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"krb5-32bit-1.10.2-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"krb5-debuginfo-32bit-1.10.2-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"krb5-devel-32bit-1.10.2-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"krb5-1.10.2-10.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"krb5-client-1.10.2-10.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"krb5-client-debuginfo-1.10.2-10.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"krb5-debuginfo-1.10.2-10.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"krb5-debugsource-1.10.2-10.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"krb5-devel-1.10.2-10.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"krb5-mini-1.10.2-10.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"krb5-mini-debuginfo-1.10.2-10.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"krb5-mini-debugsource-1.10.2-10.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"krb5-mini-devel-1.10.2-10.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"krb5-plugin-kdb-ldap-1.10.2-10.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"krb5-plugin-kdb-ldap-debuginfo-1.10.2-10.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"krb5-plugin-preauth-pkinit-1.10.2-10.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"krb5-plugin-preauth-pkinit-debuginfo-1.10.2-10.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"krb5-server-1.10.2-10.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"krb5-server-debuginfo-1.10.2-10.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"krb5-32bit-1.10.2-10.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"krb5-debuginfo-32bit-1.10.2-10.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"krb5-devel-32bit-1.10.2-10.13.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5 / krb5-32bit / krb5-client / krb5-client-debuginfo / etc");
}
