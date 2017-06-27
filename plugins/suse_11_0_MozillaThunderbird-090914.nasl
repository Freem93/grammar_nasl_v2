#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update MozillaThunderbird-1303.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(41009);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/06/13 19:44:03 $");

  script_cve_id("CVE-2009-2408");

  script_name(english:"openSUSE Security Update : MozillaThunderbird (MozillaThunderbird-1303)");
  script_summary(english:"Check for the MozillaThunderbird-1303 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Thunderbird was updated to version 2.0.0.23.

The release fixes one security issue: MFSA 2009-42 / CVE-2009-2408:
IOActive security researcher Dan Kaminsky reported a mismatch in the
treatment of domain names in SSL certificates between SSL clients and
the Certificate Authorities (CA) which issue server certificates. In
particular, if a malicious person requested a certificate for a host
name with an invalid null character in it most CAs would issue the
certificate if the requester owned the domain specified after the
null, while most SSL clients (browsers) ignored that part of the name
and used the unvalidated part in front of the null. This made it
possible for attackers to obtain certificates that would function for
any site they wished to target. These certificates could be used to
intercept and potentially alter encrypted communication between the
client and a server such as sensitive bank account transactions. This
vulnerability was independently reported to us by researcher Moxie
Marlinspike who also noted that since Firefox relies on SSL to protect
the integrity of security updates this attack could be used to serve
malicious updates."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=534782"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaThunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hunspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hunspell-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.0", reference:"MozillaThunderbird-2.0.0.23-0.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"MozillaThunderbird-devel-2.0.0.23-0.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"MozillaThunderbird-translations-2.0.0.23-0.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"hunspell-1.2.2-15.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"hunspell-32bit-1.2.2-15.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaThunderbird");
}
