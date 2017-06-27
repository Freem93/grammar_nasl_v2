#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(34967);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/22 20:32:46 $");

  script_cve_id("CVE-2008-0017", "CVE-2008-5012", "CVE-2008-5013", "CVE-2008-5014", "CVE-2008-5016", "CVE-2008-5017", "CVE-2008-5018", "CVE-2008-5021", "CVE-2008-5022", "CVE-2008-5023", "CVE-2008-5024", "CVE-2008-5052");

  script_name(english:"SuSE 10 Security Update : gecko-sdk and mozilla-xulrunner (ZYPP Patch Number 5811)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update backports the latest security fixes to the Mozilla
XULRunner engine.

It fixes following security issues :

  - The http-index-format MIME type parser
    (nsDirIndexParser) in Firefox 3.x before 3.0.4, Firefox
    2.x before 2.0.0.18, and SeaMonkey 1.x before 1.1.13
    does not check for an allocation failure, which allows
    remote attackers to cause a denial of service (crash)
    and possibly execute arbitrary code via an HTTP index
    response with a crafted 200 header, which triggers
    memory corruption and a buffer overflow. (CVE-2008-0017
    / MFSA 2008-54)

  - Mozilla Firefox 2.x before 2.0.0.18, Thunderbird 2.x
    before 2.0.0.18, and SeaMonkey 1.x before 1.1.13 do not
    properly change the source URI when processing a canvas
    element and an HTTP redirect, which allows remote
    attackers to bypass the same origin policy and access
    arbitrary images that are not directly accessible to the
    attacker. NOTE: this issue can be leveraged to enumerate
    software on the client by performing redirections
    related to moz-icon. (CVE-2008-5012 / MFSA 2008-48)

  - Mozilla Firefox 2.x before 2.0.0.18 and SeaMonkey 1.x
    before 1.1.13 do not properly check when the Flash
    module has been dynamically unloaded properly, which
    allows remote attackers to execute arbitrary code via a
    crafted SWF file that 'dynamically unloads itself from
    an outside JavaScript function,' which triggers an
    access of an expired memory address. (CVE-2008-5013 /
    MFSA 2008-49)

  - jslock.cpp in Mozilla Firefox 3.x before 3.0.2, Firefox
    2.x before 2.0.0.18, Thunderbird 2.x before 2.0.0.18,
    and SeaMonkey 1.x before 1.1.13 allows remote attackers
    to cause a denial of service (crash) and possibly
    execute arbitrary code by modifying the
    window.__proto__.__proto__ object in a way that causes a
    lock on a non-native object, which triggers an assertion
    failure related to the OBJ_IS_NATIVE function.
    (CVE-2008-5014 / MFSA 2008-50)

  - The layout engine in Mozilla Firefox 3.x before 3.0.4,
    Thunderbird 2.x before 2.0.0.18, and SeaMonkey 1.x
    before 1.1.13 allows remote attackers to cause a denial
    of service (crash) via multiple vectors that trigger an
    assertion failure or other consequences. (CVE-2008-5016
    / MFSA 2008-52)

  - Integer overflow in xpcom/io/nsEscape.cpp in the browser
    engine in Mozilla Firefox 3.x before 3.0.4, Firefox 2.x
    before 2.0.0.18, Thunderbird 2.x before 2.0.0.18, and
    SeaMonkey 1.x before 1.1.13 allows remote attackers to
    cause a denial of service (crash) via unknown vectors.
    (CVE-2008-5017 / MFSA 2008-52)

  - The JavaScript engine in Mozilla Firefox 3.x before
    3.0.4, Firefox 2.x before 2.0.0.18, Thunderbird 2.x
    before 2.0.0.18, and SeaMonkey 1.x before 1.1.13 allows
    remote attackers to cause a denial of service (crash)
    via vectors related to 'insufficient class checking' in
    the Date class. (CVE-2008-5018 / MFSA 2008-52)

  - nsFrameManager in Firefox 3.x before 3.0.4, Firefox 2.x
    before 2.0.0.18, Thunderbird 2.x before 2.0.0.18, and
    SeaMonkey 1.x before 1.1.13 allows remote attackers to
    cause a denial of service (crash) and possibly execute
    arbitrary code by modifying properties of a file input
    element while it is still being initialized, then using
    the blur method to access uninitialized memory.
    (CVE-2008-5021 / MFSA 2008-55)

  - The nsXMLHttpRequest::NotifyEventListeners method in
    Firefox 3.x before 3.0.4, Firefox 2.x before 2.0.0.18,
    Thunderbird 2.x before 2.0.0.18, and SeaMonkey 1.x
    before 1.1.13 allows remote attackers to bypass the
    same-origin policy and execute arbitrary script via
    multiple listeners, which bypass the inner window check.
    (CVE-2008-5022 / MFSA 2008-56)

  - Firefox 3.x before 3.0.4, Firefox 2.x before 2.0.0.18,
    and SeaMonkey 1.x before 1.1.13 allows remote attackers
    to bypass the protection mechanism for codebase
    principals and execute arbitrary script via the
    -moz-binding CSS property in a signed JAR file.
    (CVE-2008-5023 / MFSA 2008-57)

  - Mozilla Firefox 3.x before 3.0.4, Firefox 2.x before
    2.0.0.18, Thunderbird 2.x before 2.0.0.18, and SeaMonkey
    1.x before 1.1.13 do not properly escape quote
    characters used for XML processing, allows remote
    attackers to conduct XML injection attacks via the
    default namespace in an E4X document. (CVE-2008-5024 /
    MFSA 2008-58)

  - The AppendAttributeValue function in the JavaScript
    engine in Mozilla Firefox 2.x before 2.0.0.18,
    Thunderbird 2.x before 2.0.0.18, and SeaMonkey 1.x
    before 1.1.13 allows remote attackers to cause a denial
    of service (crash) via unknown vectors that trigger
    memory corruption, as demonstrated by
    e4x/extensions/regress-410192.js. (CVE-2008-5052 / MFSA
    2008-52)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-48.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-49.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-50.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-52.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-54.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-55.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-56.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-57.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-58.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-0017.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5012.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5013.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5014.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5016.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5017.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5018.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5021.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5022.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5023.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5024.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5052.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 5811.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 94, 119, 189, 200, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/11/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:1, reference:"gecko-sdk-1.8.0.14eol-0.9")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"mozilla-xulrunner-1.8.0.14eol-0.9")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner-32bit-1.8.0.14eol-0.9")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"mozilla-xulrunner-1.8.0.14eol-0.9")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner-32bit-1.8.0.14eol-0.9")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
