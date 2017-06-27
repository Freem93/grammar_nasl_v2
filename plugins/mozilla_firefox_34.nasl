#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79665);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/16 14:12:50 $");

  script_cve_id(
    "CVE-2014-1569",
    "CVE-2014-1587",
    "CVE-2014-1588",
    "CVE-2014-1589",
    "CVE-2014-1590",
    "CVE-2014-1591",
    "CVE-2014-1592",
    "CVE-2014-1593",
    "CVE-2014-1594",
    "CVE-2014-8631",
    "CVE-2014-8632"
  );
  script_bugtraq_id(71391, 71392, 71393, 71395, 71396, 71397, 71398, 71399, 71556, 71560, 71675);
  script_osvdb_id(115195, 115196, 115197, 115198, 115199, 115200, 115202, 115260, 115261, 115397);

  script_name(english:"Firefox < 34.0 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Windows host is a
version prior to 34.0. It is, therefore, affected by the following
vulnerabilities :

  - A security bypass vulnerability exists due to the
    'XrayWrappers' filter not properly validating object
    properties. This allows a remote attacker to bypass
    security protection mechanisms to access protected
    objects. (CVE-2014-8631)

  - A security bypass vulnerability exists due to Chrome
    Object Wrappers (COW) being passed as native interfaces.
    This allows a remote attacker to access normally
    protected objects. (CVE-2014-8632)

  - A remote code execution vulnerability exists in Mozilla
    Network Security Services (NSS) due to a flaw in
    'quickder.c' that is triggered when handling PKCS#1
    signatures during the decoding of ASN.1 DER.
    (CVE-2014-1569)

  - Multiple memory safety flaws exist within the browser
    engine. Exploiting these, an attacker can cause a denial
    of service or execute arbitrary code. (CVE-2014-1587,
    CVE-2014-1588)

  - A security bypass vulnerability exists due improper
    declaration of chrome accessible CSS primary namespaces
    allowing for XML Binding Language (XBL) bindings to be
    triggered remotely. (CVE-2014-1589)

  - A denial of service vulnerability exists due to
    improper parsing of a JavaScript object to the
    XMLHttpRequest API which can result in a crash.
    (CVE-2014-1590)

  - An information disclosure vulnerability exists due to
    Content Security Policy (CSP) violation reports
    triggered by a redirect not properly removing path
    information which can reveal sensitive information.
    Note that this only affects Firefox 33. (CVE-2014-1591)

  - A use-after-free error exists due the creation of a
    second XML root element when parsing HTML written to a
    document created with 'document.open()' function which
    can result in arbitrary code execution. (CVE-2014-1592)

  - A buffer overflow vulnerability exists in the
    'mozilla::FileBlockCache::Read' function when parsing
    media which can result in arbitrary code execution.
    (CVE-2014-1593)

  - A casting error exists when casting from the
    'BasicThebesLayer' layer to the 'BasicContainerLayer'
    layer which can result in arbitrary code execution.
    (CVE-2014-1594)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-83/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-84/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-85/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-86/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-87/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-88/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-89/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-91/");

  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 34.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'34.0', severity:SECURITY_HOLE, xss:FALSE);
