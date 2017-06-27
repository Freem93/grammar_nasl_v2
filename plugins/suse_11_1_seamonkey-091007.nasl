#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update seamonkey-1364.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(42206);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/21 20:21:19 $");

  script_cve_id("CVE-2009-1307", "CVE-2009-1311", "CVE-2009-1392", "CVE-2009-1832", "CVE-2009-1833", "CVE-2009-1835", "CVE-2009-1836", "CVE-2009-1838", "CVE-2009-1841", "CVE-2009-2210", "CVE-2009-2404", "CVE-2009-2408");

  script_name(english:"openSUSE Security Update : seamonkey (seamonkey-1364)");
  script_summary(english:"Check for the seamonkey-1364 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"seamonkey was updated to version 1.1.18, fixing various security
issues :

MFSA 2009-43 / CVE-2009-2404 Moxie Marlinspike reported a heap
overflow vulnerability in the code that handles regular expressions in
certificate names. This vulnerability could be used to compromise the
browser and run arbitrary code by presenting a specially crafted
certificate to the client. This code provided compatibility with the
non-standard regular expression syntax historically supported by
Netscape clients and servers. With version 3.5 Firefox switched to the
more limited industry-standard wildcard syntax instead and is not
vulnerable to this flaw. 

MFSA 2009-42 / CVE-2009-2408: IOActive security researcher Dan
Kaminsky reported a mismatch in the treatment of domain names in SSL
certificates between SSL clients and the Certificate Authorities (CA)
which issue server certificates. In particular, if a malicious person
requested a certificate for a host name with an invalid null character
in it most CAs would issue the certificate if the requester owned the
domain specified after the null, while most SSL clients (browsers)
ignored that part of the name and used the unvalidated part in front
of the null. This made it possible for attackers to obtain
certificates that would function for any site they wished to target.
These certificates could be used to intercept and potentially alter
encrypted communication between the client and a server such as
sensitive bank account transactions. This vulnerability was
independently reported to us by researcher Moxie Marlinspike who also
noted that since Firefox relies on SSL to protect the integrity of
security updates this attack could be used to serve malicious updates.
Mozilla would like to thank Dan and the Microsoft Vulnerability
Research team for coordinating a multiple-vendor response to this
problem.

The update also contains the fixes from the skipped 1.1.17 security
update: MFSA 2009-17/CVE-2009-1307: Same-origin violations when Adobe
Flash loaded via view-source: scheme 

MFSA 2009-21/CVE-2009-1311:POST data sent to wrong site when saving
web page with embedded frame 

MFSA 2009-24/CVE-2009-1392/CVE-2009-1832/CVE-2009-1833: Crashes with
evidence of memory corruption (rv:1.9.0.11) 

MFSA 2009-26/CVE-2009-1835: Arbitrary domain cookie access by local
file: resources 

MFSA 2009-27/CVE-2009-1836: SSL tampering via non-200 responses to
proxy CONNECT requests 

MFSA 2009-29/CVE-2009-1838: Arbitrary code execution using event
listeners attached to an element whose owner document is null 

MFSA 2009-32/CVE-2009-1841: JavaScript chrome privilege escalation
MFSA 2009-33/CVE-2009-2210: Crash viewing multipart/alternative
message with text/enhanced part"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=515951"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=544910"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected seamonkey packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 94, 119, 200, 287, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-irc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-spellchecker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-venkman");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/22");
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
if (release !~ "^(SUSE11\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.1", reference:"seamonkey-1.1.18-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"seamonkey-dom-inspector-1.1.18-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"seamonkey-irc-1.1.18-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"seamonkey-mail-1.1.18-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"seamonkey-spellchecker-1.1.18-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"seamonkey-venkman-1.1.18-0.1.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "seamonkey");
}
