#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update MozillaFirefox-1585.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27112);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/22 20:42:27 $");

  script_cve_id("CVE-2006-1729", "CVE-2006-1942", "CVE-2006-2775", "CVE-2006-2776", "CVE-2006-2777", "CVE-2006-2778", "CVE-2006-2779", "CVE-2006-2780", "CVE-2006-2782", "CVE-2006-2783", "CVE-2006-2784", "CVE-2006-2785", "CVE-2006-2786", "CVE-2006-2787");

  script_name(english:"openSUSE 10 Security Update : MozillaFirefox (MozillaFirefox-1585)");
  script_summary(english:"Check for the MozillaFirefox-1585 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This updates fixes several security problems in the Mozilla Firefox
1.5 browser and brings it up to 1.5.0.4 bugfix level. The full list is
at:
http://www.mozilla.org/projects/security/known-vulnerabilities.html#fi
refox1.5.0.4 MFSA 2006-31/CVE-2006-2787: EvalInSandbox allows remote
attackers to gain privileges via JavaScript that calls the valueOf
method on objects that were created outside of the sandbox. MFSA
2006-32/CVE-2006-2780: An Integer overflow allows remote attackers to
cause a denial of service (crash) and possibly execute arbitrary code
via 'jsstr tagify,' which leads to memory corruption. MFSA
2006-32/CVE-2006-2779: Firefox allow remote attackers to cause a
denial of service (crash) and possibly execute arbitrary code via (1)
nested <option> tags in a select tag, (2) a DOMNodeRemoved mutation
event, (3) 'Content-implemented tree views,' (4) BoxObjects, (5) the
XBL implementation, (6) an iframe that attempts to remove itself,
which leads to memory corruption. MFSA 2006-33/CVE-2006-2786: HTTP
response smuggling vulnerability in Mozilla Firefox, when used with
certain proxy servers, allows remote attackers to cause Firefox to
interpret certain responses as if they were responses from two
different sites via (1) invalid HTTP response headers with spaces
between the header name and the colon, which might not be ignored in
some cases, or (2) HTTP 1.1 headers through an HTTP 1.0 proxy, which
are ignored by the proxy but processed by the client. MFSA
2006-34/CVE-2006-2785: Cross-site scripting (XSS) vulnerability in
Mozilla Firefox allows user-complicit remote attackers to inject
arbitrary web script or HTML by tricking a user into (1) performing a
'View Image' on a broken image in which the SRC attribute contains a
JavaScript URL, or (2) selecting 'Show only this frame' on a frame
whose SRC attribute contains a JavaScript URL. MFSA
2006-35/CVE-2006-2775: Mozilla Firefox associates XUL attributes with
the wrong URL under certain unspecified circumstances, which might
allow remote attackers to bypass restrictions by causing a persisted
string to be associated with the wrong URL. MFSA
2006-36/CVE-2006-2784: The PLUGINSPAGE functionality in Mozilla
Firefox allows remote user-complicit attackers to execute privileged
code by tricking a user into installing missing plugins and selecting
the 'Manual Install' button, then using nested javascript: URLs. MFSA
2006-37/CVE-2006-2776: Certain privileged UI code in Mozilla Firefox
calls content-defined setters on an object prototype, which allows
remote attackers to execute code at a higher privilege than intended.
MFSA 2006-38/CVE-2006-2778: The crypto.signText function in Mozilla
Firefox allows remote attackers to execute arbitrary code via certain
optional Certificate Authority name arguments, which causes an invalid
array index and triggers a buffer overflow. MFSA
2006-39/CVE-2006-1942: Mozilla Firefox allows user-complicit remote
attackers to open local files via a web page with an IMG element
containing a SRC attribute with a non-image file:// URL, then tricking
the user into selecting View Image for the broken image, as
demonstrated using a ,wma file to launch Windows Media Player, or by
referencing an 'alternate web page.' MFSA-2006-41/CVE-2006-2782:
Firefox does not fix all test cases associated with CVE-2006-1729,
which allows remote attackers to read arbitrary files by inserting the
target filename into a text box, then turning that box into a file
upload control. MFSA 2006-42/CVE-2006-2783: Mozilla Firefox strips the
Unicode Byte-order-Mark (BOM) from a UTF-8 page before the page is
passed to the parser, which allows remote attackers to conduct
cross-site scripting (XSS) attacks via a BOM sequence in the middle of
a dangerous tag such as SCRIPT. MFSA 2006-43/CVE-2006-2777:
Unspecified vulnerability in Mozilla Firefox allows remote attackers
to execute arbitrary code by using the nsISelectionPrivate interface
of the Selection object to add a SelectionListener and create
notifications that are executed in a privileged context."
  );
  # http://www.mozilla.org/projects/security/known-vulnerabilities.html#firefox1.5.0.4
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?06d18f6d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686)$") audit(AUDIT_ARCH_NOT, "i586 / i686", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"MozillaFirefox-1.5.0.4-1.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"MozillaFirefox-translations-1.5.0.4-1.3") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox / MozillaFirefox-translations");
}
