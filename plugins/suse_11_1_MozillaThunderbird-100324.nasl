#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update MozillaThunderbird-2189.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(45376);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/21 20:21:18 $");

  script_cve_id("CVE-2009-0689", "CVE-2009-2463", "CVE-2009-3072", "CVE-2009-3075", "CVE-2009-3077", "CVE-2009-3376", "CVE-2009-3983", "CVE-2010-0161", "CVE-2010-0163");

  script_name(english:"openSUSE Security Update : MozillaThunderbird (MozillaThunderbird-2189)");
  script_summary(english:"Check for the MozillaThunderbird-2189 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Thunderbird was updated to 2.0.0.14 fixing several security
issues and bugs.

MFSA 2010-07: Mozilla developers took fixes from previously fixed
memory safety bugs in newer Mozilla-based products and ported them to
the Mozilla 1.8.1 branch so they can be utilized by Thunderbird 2 and
SeaMonkey 1.1.

Paul Fisher reported a crash when joined to an Active Directory server
under Vista or Windows 7 and using SSPI authentication.
(CVE-2010-0161) Ludovic Hirlimann reported a crash indexing some
messages with attachments (CVE-2010-0163) Carsten Book reported a
crash in the JavaScript engine (CVE-2009-3075) Josh Soref reported a
crash in the BinHex decoder used on non-Mac platforms. (CVE-2009-3072)
monarch2000 reported an integer overflow in a base64 decoding function
(CVE-2009-2463)

MFSA 2009-68 / CVE-2009-3983: Security researcher Takehiro Takahashi
of the IBM X-Force reported that Mozilla's NTLM implementation was
vulnerable to reflection attacks in which NTLM credentials from one
application could be forwarded to another arbitary application via the
browser. If an attacker could get a user to visit a web page he
controlled he could force NTLM authenticated requests to be forwarded
to another application on behalf of the user.

MFSA 2009-62 / CVE-2009-3376: Mozilla security researchers Jesse
Ruderman and Sid Stamm reported that when downloading a file
containing a right-to-left override character (RTL) in the filename,
the name displayed in the dialog title bar conflicts with the name of
the file shown in the dialog body. An attacker could use this
vulnerability to obfuscate the name and file extension of a file to be
downloaded and opened, potentially causing a user to run an executable
file when they expected to open a non-executable file.

MFSA 2009-59 / CVE-2009-0689: Security researcher Alin Rad Pop of
Secunia Research reported a heap-based buffer overflow in Mozilla's
string to floating point number conversion routines. Using this
vulnerability an attacker could craft some malicious JavaScript code
containing a very long string to be converted to a floating point
number which would result in improper memory allocation and the
execution of an arbitrary memory location. This vulnerability could
thus be leveraged by the attacker to run arbitrary code on a victim's
computer.

Update: The underlying flaw in the dtoa routines used by Mozilla
appears to be essentially the same as that reported against the libc
gdtoa routine by Maksymilian Arciemowicz.

MFSA 2009-49 / CVE-2009-3077: An anonymous security researcher, via
TippingPoint's Zero Day Initiative, reported that the columns of a XUL
tree element could be manipulated in a particular way which would
leave a pointer owned by the column pointing to freed memory. An
attacker could potentially use this vulnerability to crash a victim's
browser and run arbitrary code on the victim's computer.

Please see
http://www.mozilla.org/security/known-vulnerabilities/thunderbird20.ht
ml"
  );
  # http://www.mozilla.org/security/known-vulnerabilities/thunderbird20.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?280be806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=576969"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaThunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(16, 94, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.1", reference:"MozillaThunderbird-2.0.0.24-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"MozillaThunderbird-devel-2.0.0.24-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"MozillaThunderbird-translations-2.0.0.24-0.1.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaThunderbird");
}
