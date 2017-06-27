#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(46685);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/21 20:33:29 $");

  script_cve_id("CVE-2009-0689", "CVE-2009-2463", "CVE-2009-3072", "CVE-2009-3075", "CVE-2009-3077", "CVE-2009-3376", "CVE-2009-3385", "CVE-2009-3983", "CVE-2010-0161", "CVE-2010-0163");

  script_name(english:"SuSE9 Security Update : epiphany (YOU Patch Number 12616)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 9 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update brings Mozilla SeaMonkey to 1.1.19 fixing various bugs and
security issues.

The following security issues are fixed :

  - Mozilla developers took fixes from previously fixed
    memory safety bugs in newer Mozilla-based products and
    ported them to the Mozilla 1.8.1 branch so they can be
    utilized by Thunderbird 2 and SeaMonkey 1.1. (MFSA
    2010-07)

  - Paul Fisher reported a crash when joined to an Active
    Directory server under Vista or Windows 7 and using SSPI
    authentication. (CVE-2010-0161)

  - Ludovic Hirlimann reported a crash indexing some
    messages with attachments. (CVE-2010-0163)

  - Carsten Book reported a crash in the JavaScript engine.
    (CVE-2009-3075)

  - Josh Soref reported a crash in the BinHex decoder used
    on non-Mac platforms. (CVE-2009-3072)

  - monarch2000 reported an integer overflow in a base64
    decoding function. (CVE-2009-2463)

  - Security researcher Takehiro Takahashi of the IBM
    X-Force reported that Mozilla's NTLM implementation was
    vulnerable to reflection attacks in which NTLM
    credentials from one application could be forwarded to
    another arbitary application via the browser. If an
    attacker could get a user to visit a web page he
    controlled he could force NTLM authenticated requests to
    be forwarded to another application on behalf of the
    user. (MFSA 2009-68 / CVE-2009-3983)

  - Mozilla security researchers Jesse Ruderman and Sid
    Stamm reported that when downloading a file containing a
    right-to-left override character (RTL) in the filename,
    the name displayed in the dialog title bar conflicts
    with the name of the file shown in the dialog body. An
    attacker could use this vulnerability to obfuscate the
    name and file extension of a file to be downloaded and
    opened, potentially causing a user to run an executable
    file when they expected to open a non-executable file.
    (MFSA 2009-62 / CVE-2009-3376)

  - Security researcher Alin Rad Pop of Secunia Research
    reported a heap-based buffer overflow in Mozilla's
    string to floating point number conversion routines.
    Using this vulnerability an attacker could craft some
    malicious JavaScript code containing a very long string
    to be converted to a floating point number which would
    result in improper memory allocation and the execution
    of an arbitrary memory location. This vulnerability
    could thus be leveraged by the attacker to run arbitrary
    code on a victim's computer. (MFSA 2009-59 /
    CVE-2009-0689)

Update: The underlying flaw in the dtoa routines used by Mozilla
appears to be essentially the same as that reported against the libc
gdtoa routine by Maksymilian Arciemowicz.

  - Security researcher Georgi Guninski reported that
    scriptable plugin content, such as Flash objects, could
    be loaded and executed in SeaMonkey mail messages by
    embedding the content in an iframe inside the message.
    If a user were to reply to or forward such a message,
    malicious JavaScript embedded in the plugin content
    could potentially steal the contents of the message or
    files from the local filesystem. (MFSA 2010-06 /
    CVE-2009-3385)

  - An anonymous security researcher, via TippingPoint's
    Zero Day Initiative, reported that the columns of a XUL
    tree element could be manipulated in a particular way
    which would leave a pointer owned by the column pointing
    to freed memory. An attacker could potentially use this
    vulnerability to crash a victim's browser and run
    arbitrary code on the victim's computer. (MFSA 2009-49 /
    CVE-2009-3077)

Please see
http://www.mozilla.org/security/known-vulnerabilities/seamonkey11.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0689.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2463.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3072.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3075.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3077.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3376.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3385.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3983.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0161.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0163.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply YOU patch number 12616.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(16, 94, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 9 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SUSE9", reference:"mozilla-1.8_seamonkey_1.1.19-0.1")) flag++;
if (rpm_check(release:"SUSE9", reference:"mozilla-devel-1.8_seamonkey_1.1.19-0.1")) flag++;
if (rpm_check(release:"SUSE9", reference:"mozilla-dom-inspector-1.8_seamonkey_1.1.19-0.1")) flag++;
if (rpm_check(release:"SUSE9", reference:"mozilla-irc-1.8_seamonkey_1.1.19-0.1")) flag++;
if (rpm_check(release:"SUSE9", reference:"mozilla-mail-1.8_seamonkey_1.1.19-0.1")) flag++;
if (rpm_check(release:"SUSE9", reference:"mozilla-venkman-1.8_seamonkey_1.1.19-0.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
