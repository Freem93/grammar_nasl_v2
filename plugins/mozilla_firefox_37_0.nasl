#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82503);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/16 14:12:50 $");

  script_cve_id(
    "CVE-2015-0801",
    "CVE-2015-0802",
    "CVE-2015-0803",
    "CVE-2015-0804",
    "CVE-2015-0805",
    "CVE-2015-0806",
    "CVE-2015-0807",
    "CVE-2015-0808",
    "CVE-2015-0811",
    "CVE-2015-0812",
    "CVE-2015-0814",
    "CVE-2015-0815",
    "CVE-2015-0816"
  );
  script_bugtraq_id(
    73454,
    73455,
    73457,
    73458,
    73460,
    73461,
    73462,
    73464,
    73465,
    73466,
    73467
  );
  script_osvdb_id(
    119753,
    120077,
    120078,
    120079,
    120080,
    120081,
    120082,
    120083,
    120084,
    120085,
    120086,
    120087,
    120088,
    120089,
    120091,
    120092,
    120100,
    120101,
    120102,
    120103,
    120104,
    120105,
    120106,
    120107
  );

  script_name(english:"Firefox < 37.0 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Windows host is prior
to 37.0. It is, therefore, affected by the following vulnerabilities :

  - A privilege escalation vulnerability exists which
    relates to anchor navigation. A remote attacker can
    exploit this to bypass same-origin policy protections,
    allowing a possible execution of arbitrary scripts in a
    privileged context. Note that this is a variant of
    CVE-2015-0818 that was fixed in Firefox 36.0.4.
    (CVE-2015-0801)

  - Access to certain privileged internal methods is
    retained when navigating from windows created to contain
    privileged UI content to unprivileged pages. An attacker
    can exploit this to execute arbitrary JavaScript with
    elevated privileges. (CVE-2015-0802)

  - Multiple type confusion issues exist that can lead to
    use-after-free errors, which a remote attacker can
    exploit to execute arbitrary code or cause a denial of
    service. (CVE-2015-0803, CVE-2015-0804)

  - Multiple memory corruption issues exist related to Off
    Main Thread Compositing when rendering 2D graphics,
    which a remote attacker can exploit to execute arbitrary
    code or cause a denial of service. (CVE-2015-0805,
    CVE-2015-0806)

  - A cross-site request forgery (XSRF) vulnerability exists
    in the sendBeacon() function due to cross-origin
    resource sharing (CORS) requests following 30x
    redirections. (CVE-2015-0807)

  - An issue exists in WebRTC related to memory management
    for simple-style arrays, which may be used by a remote
    attacker to cause a denial of service. (CVE-2015-0808)

  - An out-of-bounds read issue exists in the QCMS color
    management library that could lead to an information
    disclosure. (CVE-2015-0811)

  - An issue exists that can allow a man-in-the-middle
    attacker to bypass user-confirmation and install a
    Firefox lightweight theme by spoofing a Mozilla
    sub-domain. (CVE-2015-0812)
  
  - Multiple memory safety issues exist within the browser
    engine. A remote attacker can exploit these to corrupt
    memory and possibly execute arbitrary code.
    (CVE-2015-0814, CVE-2015-0815)

  - A privilege escalation vulnerability exists related to
    documents loaded through a 'resource:' URL. An attacker
    can exploit this to load pages and execute JavaScript
    with elevated privileges. (CVE-2015-0816)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-30/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-32/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-33/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-34/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-36/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-37/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-38/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-39/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-40/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-42/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 37.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox PDF.js Privileged Javascript Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/01");

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

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'37.0', severity:SECURITY_HOLE, xss:FALSE, xsrf:TRUE);
