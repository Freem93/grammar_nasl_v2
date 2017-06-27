#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99628);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/05/12 17:36:03 $");

  script_cve_id(
    "CVE-2016-6354",
    "CVE-2016-10195",
    "CVE-2016-10196",
    "CVE-2016-10197",
    "CVE-2017-5429",
    "CVE-2017-5430",
    "CVE-2017-5432",
    "CVE-2017-5433",
    "CVE-2017-5434",
    "CVE-2017-5435",
    "CVE-2017-5436",
    "CVE-2017-5437",
    "CVE-2017-5438",
    "CVE-2017-5439",
    "CVE-2017-5440",
    "CVE-2017-5441",
    "CVE-2017-5442",
    "CVE-2017-5443",
    "CVE-2017-5444",
    "CVE-2017-5445",
    "CVE-2017-5446",
    "CVE-2017-5447",
    "CVE-2017-5448",
    "CVE-2017-5449",
    "CVE-2017-5451",
    "CVE-2017-5454",
    "CVE-2017-5455",
    "CVE-2017-5456",
    "CVE-2017-5459",
    "CVE-2017-5460",
    "CVE-2017-5461",
    "CVE-2017-5462",
    "CVE-2017-5464",
    "CVE-2017-5465",
    "CVE-2017-5466",
    "CVE-2017-5467",
    "CVE-2017-5469"
  );
  script_bugtraq_id(
    92141,
    96014,
    97940
  );
  script_osvdb_id(
    142032,
    151245,
    151246,
    151247,
    155950,
    155951,
    155952,
    155953,
    155954,
    155955,
    155956,
    155957,
    155958,
    155959,
    155960,
    155961,
    155962,
    155963,
    155964,
    155965,
    155966,
    155967,
    155968,
    155972,
    155973,
    155974,
    155975,
    155976,
    155989,
    155991,
    155992,
    155999,
    156037,
    156038,
    156039,
    156040,
    156041,
    156042,
    156043,
    156044,
    156045,
    156046,
    156047,
    156048,
    156049,
    156050,
    156051,
    156052,
    156053,
    156054,
    156055,
    156056,
    156057,
    156058,
    156059
  );
  script_xref(name:"MFSA", value:"2017-12");

  script_name(english:"Mozilla Firefox ESR < 52.1 Multiple Vulnerabilities (macOS)");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote macOS or Mac OS X host contains a web browser that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox ESR installed on the remote macOS or
Mac OS X host is prior to 52.1. It is, therefore, affected by the
following vulnerabilities :

  - Multiple buffer overflow conditions exist in the FLEX
    generated code due to improper validation of certain
    input. An unauthenticated, remote attacker can exploit
    these to execute arbitrary code. (CVE-2016-6354,
    CVE-2017-5469)

  - Multiple flaws exist in the Libevent library, within
    files evdns.c and evutil.c, due to improper validation
    of input when handling IP address strings, empty base
    name strings, and DNS packets. An unauthenticated,
    remote attacker can exploit these to cause a denial of
    service condition or the execution of arbitrary code.
    (CVE-2016-10195, CVE-2016-10196, CVE-2016-10197,
    CVE-2017-5437)

  - Multiple memory corruption issues exist that allow an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2017-5429, CVE-2017-5430)

  - A use-after-free error exists in input text selection
    that allows an unauthenticated, remote attacker to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2017-5432)

  - A use-after-free error exists in the SMIL animation
    functions when handling animation elements. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2017-5433)

  - A use-after-free error exists when redirecting focus
    handling that allows an unauthenticated, remote attacker
    to cause a denial of service condition or the execution
    of arbitrary code. (CVE-2017-5434)

  - A use-after-free error exists in design mode
    interactions when handling transaction processing in
    the editor. An unauthenticated, remote attacker can
    exploit this to cause a denial of service condition or
    the execution of arbitrary code. (CVE-2017-5435)

  - An out-of-bounds write error exists in the Graphite 2
    library when handling specially crafted Graphite fonts.
    An unauthenticated, remote attacker can exploit this to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2017-5436)

  - A use-after-free error exists in the nsAutoPtr()
    function during XSLT processing due to the result
    handler being held by a freed handler. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2017-5438)

  - A use-after-free error exists in the Length() function
    in nsTArray when handling template parameters during
    XSLT processing. An unauthenticated, remote attacker can
    exploit this to cause a denial of service condition or
    the execution of arbitrary code. (CVE-2017-5439)

  - A use-after-free error exists in the txExecutionState
    destructor when processing XSLT content. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2017-5440)

  - A use-after-free error exists when holding a selection
    during scroll events. An unauthenticated, remote
    attacker can exploit this to cause a denial of service
    condition or the execution of arbitrary code.
    (CVE-2017-5441)

  - A use-after-free error exists when changing styles in
    DOM elements that allows an unauthenticated, remote
    attacker to cause a denial of service condition or the
    execution of arbitrary code. (CVE-2017-5442)

  - An out-of-bounds write error exists while decoding
    improperly formed BinHex format archives that allows an
    unauthenticated, remote attacker to cause a denial of
    service condition or the execution of arbitrary code.
    (CVE-2017-5443)

  - A buffer overflow condition exists while parsing
    application/http-index-format format content due to
    improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this, via
    improperly formatted data, to disclose out-of-bounds
    memory content. (CVE-2017-5444)

  - A flaw exists in nsDirIndexParser.cpp when parsing
    application/http-index-format format content in which
    uninitialized values are used to create an array. An
    unauthenticated, remote attacker can exploit this to
    disclose memory contents. (CVE-2017-5445)

  - An out-of-bounds read error exists when handling HTTP/2
    DATA connections to a server that sends DATA frames with
    incorrect content. An unauthenticated, remote attacker
    can exploit to cause a denial of service condition or
    the disclosure of memory contents. (CVE-2017-5446)

  - An out-of-bounds read error exists when processing glyph
    widths during text layout. An unauthenticated, remote
    attacker can exploit this to cause a denial of service
    condition or the disclosure of memory contents.
    (CVE-2017-5447)

  - An out-of-bounds write error exists in the
    ClearKeyDecryptor::Decrypt() function within file
    ClearKeyDecryptionManager.cpp when decrypting
    Clearkey-encrypted media content. An unauthenticated,
    remote attacker can exploit this to cause a denial of
    service condition or the execution of arbitrary code.
    This vulnerability can only be exploited if a secondary
    mechanism can be used to escape the Gecko Media Plugin
    (GMP) sandbox. (CVE-2017-5448)

  - A flaw exists when handling bidirectional Unicode text
    in conjunction with CSS animations that allows an
    unauthenticated, remote attacker to cause a denial of
    service condition or the execution or arbitrary code.
    (CVE-2017-5449)

  - A flaw exists in the handling of specially crafted
    'onblur' events. An unauthenticated, remote attacker can
    exploit this, via a specially crafted event, to spoof
    the address bar, making the loaded site appear to be
    different from the one actually loaded. (CVE-2017-5451)

  - A flaw exists in the FileSystemSecurity::Forget()
    function within file FileSystemSecurity.cpp when using
    the File Picker due to improper sanitization of input
    containing path traversal sequences. An unauthenticated,
    remote attacker can exploit this to bypass file system
    access protections in the sandbox and read arbitrary
    files on the local file system. (CVE-2017-5454)

  - An unspecified flaw exists in the internal feed reader
    APIs when handling messages. An unauthenticated, remote
    attacker can exploit this to escape the sandbox and
    gain elevated privileges if it can be combined with
    another vulnerability that allows remote code execution
    inside the sandboxed process. (CVE-2017-5455)

  - A flaw exists in the Entries API when using a file
    system request constructor through an IPC message. An
    unauthenticated, remote attacker can exploit this to
    bypass file system access protections in the sandbox
    and gain read and write access to the local file system.
    (CVE-2017-5456)

  - A buffer overflow condition exists in WebGL when
    handling web content due to improper validation of
    certain input. An unauthenticated, remote attacker can
    exploit this to cause a denial of service condition or
    the execution of arbitrary code. (CVE-2017-5459)

  - A use-after-free error exists in frame selection when
    handling a specially crafted combination of script
    content and key presses by the user. An unauthenticated,
    remote attacker can exploit this to cause a denial of
    service condition or the execution of arbitrary code.
    (CVE-2017-5460)

  - An out-of-bounds write error exists in the Network
    Security Services (NSS) library during Base64 decoding
    operations due to insufficient memory being allocated to
    a buffer. An unauthenticated, remote attacker can
    exploit this to cause a denial of service condition or
    the execution of arbitrary code. (CVE-2017-5461)

  - A flaw exists in the Network Security Services (NSS)
    library during DRBG number generation due to the
    internal state V not correctly carrying bits over. An
    unauthenticated, remote attacker can exploit this to
    potentially cause predictable random number generation.
    (CVE-2017-5462)

  - A flaw exists when making changes to DOM content in the
    accessibility tree due to improper validation of certain
    input, which can lead to the DOM tree becoming out of
    sync with the accessibility tree. An unauthenticated,
    remote attacker can exploit this to corrupt memory,
    resulting in a denial of service condition or the
    execution of arbitrary code. (CVE-2017-5464)

  - An out-of-bounds read error exists in ConvolvePixel when
    processing SVG content, which allows for otherwise
    inaccessible memory being copied into SVG graphic
    content. An unauthenticated, remote attacker can exploit
    this to disclose memory contents or cause a denial of
    service condition. (CVE-2017-5465)

  - A cross-site script (XSS) vulnerability exists due to
    improper handling of data:text/html URL redirects when
    a reload is triggered, which causes the reloaded
    data:text/html page to have its origin set incorrectly.
    An unauthenticated, remote attacker can exploit this,
    via a specially crafted request, to execute arbitrary
    script code in a user's browser session. (CVE-2017-5466)

  - A memory corruption issue exists when rendering Skia
    content outside of the bounds of a clipping region due
    to improper validation of certain input. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2017-5467)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-12/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 52.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

kb_base = "MacOSX/Firefox";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

is_esr = get_kb_item(kb_base+"/is_esr");
if (isnull(is_esr)) audit(AUDIT_NOT_INST, "Mozilla Firefox ESR");

mozilla_check_version(version:version, path:path, product:'firefox', esr:TRUE, fix:'52.1', min:'52', severity:SECURITY_HOLE);
