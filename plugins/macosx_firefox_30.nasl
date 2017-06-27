#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74437);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/04/28 20:52:58 $");

  script_cve_id(
    "CVE-2014-1533",
    "CVE-2014-1534",
    "CVE-2014-1536",
    "CVE-2014-1537",
    "CVE-2014-1538",
    "CVE-2014-1539",
    "CVE-2014-1540",
    "CVE-2014-1541",
    "CVE-2014-1542"
  );
  script_bugtraq_id(
    67964,
    67965,
    67966,
    67967,
    67968,
    67971,
    67976,
    67978,
    67979
  );

  script_name(english:"Firefox < 30.0 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Mac OS X host is a
version prior to version 30.0. It is, therefore, affected by multiple
vulnerabilities :

  - Memory issues exist that could lead to arbitrary code
    execution. Note that these issues only affect Firefox
    29. (CVE-2014-1533, CVE-2014-1534)

  - An out-of-bounds read issue exists in
    'PropertyProvider::FindJustificationRange'.
    (CVE-2014-1536)

  - Use-after-free memory issues exist in
    'mozilla::dom::workers::WorkerPrivateParent',
    'nsTextEditRules::CreateMozBR', and the SMIL Animation
    Controller that could lead to code execution.
    (CVE-2014-1537, CVE-2014-1538, CVE-2014-1541)

  - An issue exists when the cursor is used on an embedded
    Flash object which can make the cursor invisible and
    lead to clickjacking attacks. (CVE-2014-1539)

  - A use-after-free memory issue exists in the event
    listener manager. Note that this issue only affects
    Firefox 29. (CVE-2014-1540)

  - A buffer overflow issue exists in the Speex resampler
    for Web Audio that could lead to code execution.
    (CVE-2014-1542)");

  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-48.html");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-49.html");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-50.html");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-51.html");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-52.html");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-53.html");

  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 30.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Installed");

  exit(0);
}

include("mozilla_version.inc");

kb_base = "MacOSX/Firefox";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

if (get_kb_item(kb_base + '/is_esr')) exit(0, 'The Mozilla Firefox installation is in the ESR branch.');

mozilla_check_version(product:'firefox', version:version, path:path, esr:FALSE, fix:'30.0', severity:SECURITY_HOLE, xss:FALSE);
