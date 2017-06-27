#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Updates.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(42856);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/27 14:13:22 $");

  script_cve_id("CVE-2009-3555");
  script_bugtraq_id(36935);
  script_osvdb_id(59971);

  script_name(english:"SuSE 11.2 Security Update: libopenssl-devel (2009-11-13)");
  script_summary(english:"Check for the openssl packages.");

  script_set_attribute(attribute:"synopsis", value:"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The TLS/SSLv3 protocol as implemented in openssl prior to this update
was not able to associate data to a renegotiated connection. This
allowed man-in-the-middle attackers to inject HTTP requests in a HTTPS
session without being noticed. For example Apache's mod_ssl was
vulnerable to this kind of attack because it uses openssl. Please note
that renegotiation will be disabled by this update and may cause
problems in some cases. (CVE-2009-3555)");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.novell.com/show_bug.cgi?id=553641");
  script_set_attribute(attribute:"solution", value:"Update the affected openssl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl0_9_8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl0_9_8-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssl-certs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/19");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.2", reference:"libopenssl-devel-0.9.8k-3.5.3") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libopenssl0_9_8-0.9.8k-3.5.3") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libopenssl0_9_8-32bit-0.9.8k-3.5.3") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"openssl-0.9.8k-3.5.3") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"openssl-certs-0.9.8h-28.2.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-certs / libopenssl0_9_8 / etc");
}
