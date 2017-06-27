#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87476);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/03/13 05:39:56 $");

  script_cve_id(
    "CVE-2015-7201",
    "CVE-2015-7202",
    "CVE-2015-7203",
    "CVE-2015-7204",
    "CVE-2015-7205",
    "CVE-2015-7207",
    "CVE-2015-7208",
    "CVE-2015-7210",
    "CVE-2015-7211",
    "CVE-2015-7212",
    "CVE-2015-7213",
    "CVE-2015-7214",
    "CVE-2015-7215",
    "CVE-2015-7218",
    "CVE-2015-7219",
    "CVE-2015-7220",
    "CVE-2015-7221",
    "CVE-2015-7222",
    "CVE-2015-7223"
  );
  script_bugtraq_id(
    79279,
    79280,
    79283
  );
  script_osvdb_id(
    125392,
    131845,
    131846,
    131847,
    131848,
    131849,
    131850,
    131851,
    131852,
    131853,
    131854,
    131855,
    131856,
    131857,
    131858,
    131859,
    131860,
    131861,
    131863,
    131864,
    131865,
    131866,
    131867,
    131868,
    131869,
    131870,
    131871,
    131872,
    131873,
    131874,
    131875,
    131902,
    131903
  );

  script_name(english:"Firefox < 43 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Windows host is prior
to 43. It is, therefore, affected by the following vulnerabilities :

  - Multiple unspecified memory corruption issues exist due
    to improper validation of user-supplied input. A remote
    attacker can exploit these issues by convincing a user
    to visit a specially crafted web page, resulting in the
    execution of arbitrary code. (CVE-2015-7201)

  - Multiple unspecified memory corruption issues exist due
    to improper validation of user-supplied input. A remote
    attacker can exploit these issues by convincing a user
    to visit a specially crafted web page, resulting in the
    execution of arbitrary code. (CVE-2015-7202)

  - An overflow condition exists in the LoadFontFamilyData()
    function due to improper validation of user-supplied
    input. A remote attacker can exploit this to cause a
    buffer overflow, resulting in the execution of arbitrary
    code. (CVE-2015-7203)

  - A flaw exists in the PropertyWriteNeedsTypeBarrier()
    function due to improper handling of unboxed objects
    during JavaScript variable assignments. A remote
    attacker can exploit this to execute arbitrary code.
    (CVE-2015-7204)

  - A flaw exists in the RtpHeaderParser::Parse() function
    due to improper handling of RTP headers. An
    unauthenticated, remote attacker can exploit this, via
    specially crafted RTP headers, to execute arbitrary
    code. (CVE-2015-7205)

  - A same-origin bypass vulnerability exists that is
    triggered after a redirect when the function is used
    alongside an iframe to host a page. An attacker can
    exploit this to gain access to cross-origin URL
    information. (CVE-2015-7207)

  - The SetCookieInternal() function improperly allows
    control characters (e.g. ASCII code 11) to be inserted
    into cookies. An attacker can exploit this to inject
    cookies. (CVE-2015-7208)

  - A use-after-free error exists due to improper prevention
    of datachannel operations on closed PeerConnections. An
    attacker can exploit this to dereference already freed
    memory, resulting in the execution of arbitrary code.
    (CVE-2015-7210)

  - A flaw exists in the ParseURI() function due to improper
    handling of a hash (#) character in the data: URI. An
    attacker can exploit this to spoof the URL bar.
    (CVE-2015-7211)

  - An overflow condition exists in the AllocateForSurface()
    function due to improper validation of user-supplied
    input when handling texture allocation in graphics
    operations. An attacker can exploit this to execute
    arbitrary code. (CVE-2015-7212)

  - An integer overflow condition exists in the
    readMetaData() function due to improper validation of
    user-supplied input when handling a specially crafted
    MP4 file. An attacker can exploit this to execute
    arbitrary code. (CVE-2015-7213)

  - A same-origin bypass vulnerability exists due to
    improper handling of 'data:' and 'view-source:' URIs. An
    attacker can exploit this to read data from cross-site
    URLs and local files. (CVE-2015-7214)

  - An information disclosure vulnerability exists due to
    improper handling of error events in web workers. An
    attacker can exploit this to gain access to sensitive
    cross-origin information. (CVE-2015-7215)

  - Multiple integer underflow conditions exist due to
    improper  validation of user-supplied input when
    handling HTTP2 frames. An attacker can exploit these to
    crash the application, resulting in a denial of service.
    (CVE-2015-7218, CVE-2015-7219)

  - An overflow condition exists in the XDRBuffer::grow()
    function due to improper validation of user-supplied
    input. An attacker can exploit this to cause a buffer
    overflow, resulting in the execution of arbitrary code.
    (CVE-2015-7220)

  - An overflow condition exists in the GrowCapacity()
    function due to improper validation of user-supplied
    input. An attacker can exploit this to cause a buffer
    overflow, resulting in the execution of arbitrary code.
    (CVE-2015-7221)

  - An integer underflow condition exists in the bundled
    version of libstagefright in the parseChunk() function
    that is triggered when handling 'covr' chunks. An
    unauthenticated, remote attacker can exploit this, via
    specially crafted media content, to crash the
    application or execute arbitrary code. (CVE-2015-7222)

  - A privilege escalation vulnerability exists in the
    Extension.jsm script due to a failure to restrict
    WebExtension APIs from being injected into documents
    without WebExtension principals. An attacker can exploit
    this to conduct a cross-site scripting attack, resulting
    in the execution of arbitrary script code in a user's
    browser session. (CVE-2015-7223)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-134/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-135/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-136/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-137/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-138/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-139/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-140/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-141/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-142/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-144/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-145/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-146/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-147/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-148/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-149/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 43 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'43', severity:SECURITY_HOLE);
