#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update samba-3350.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27430);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2014/06/13 20:36:49 $");

  script_cve_id("CVE-2007-2444", "CVE-2007-2446", "CVE-2007-2447");

  script_name(english:"openSUSE 10 Security Update : samba (samba-3350)");
  script_summary(english:"Check for the samba-3350 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Specially crafted MS-RPC packets could overwrite heap memory and
therfore could potentially be exploited to execute code
(CVE-2007-2446).

Authenticated users could leverage specially crafted MS-RPC packets to
pass arguments unfiltered to /bin/sh (CVE-2007-2447).

A bug in the local SID/Name translation routines may potentially
result in a user being able to issue SMB protocol operations as root
(CVE-2007-2444)."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba "username map script" Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmsrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmsrpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.2", reference:"libmsrpc-3.0.23d-19.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"libmsrpc-devel-3.0.23d-19.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"libsmbclient-3.0.23d-19.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"libsmbclient-devel-3.0.23d-19.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"samba-3.0.23d-19.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"samba-client-3.0.23d-19.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"samba-python-3.0.23d-19.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"samba-winbind-3.0.23d-19.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"libsmbclient-32bit-3.0.23d-19.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"samba-32bit-3.0.23d-19.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"samba-client-32bit-3.0.23d-19.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"samba-winbind-32bit-3.0.23d-19.5") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmsrpc / libmsrpc-devel / libsmbclient / libsmbclient-32bit / etc");
}
