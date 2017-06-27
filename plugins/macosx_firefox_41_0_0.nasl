#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86069);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/04/28 20:52:58 $");

  script_cve_id(
    "CVE-2015-4500",
    "CVE-2015-4501",
    "CVE-2015-4502",
    "CVE-2015-4504",
    "CVE-2015-4506",
    "CVE-2015-4507",
    "CVE-2015-4508",
    "CVE-2015-4509",
    "CVE-2015-4510",
    "CVE-2015-4516",
    "CVE-2015-4517",
    "CVE-2015-4519",
    "CVE-2015-4520",
    "CVE-2015-4521",
    "CVE-2015-4522",
    "CVE-2015-7174",
    "CVE-2015-7175",
    "CVE-2015-7176",
    "CVE-2015-7177",
    "CVE-2015-7180"
  );
  script_osvdb_id(
    127875,
    127876,
    127877,
    127878,
    127879,
    127880,
    127881,
    127882,
    127883,
    127884,
    127888,
    127889,
    127891,
    127892,
    127893,
    127896,
    127914,
    127916,
    127917,
    127918,
    127919,
    127920,
    127921,
    127922,
    127923,
    127924
  );

  script_name(english:"Firefox < 41 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Mac OS X host is prior
to 41. It is, therefore, affected by the following vulnerabilities :

  - Multiple unspecified memory corruption issues exist due
    to improper validation of user-supplied input. A remote
    attacker can exploit these issues to corrupt memory and
    execute arbitrary code. (CVE-2015-4500)

  - Multiple unspecified memory corruption issues exist due
    to improper validation of user-supplied input. A remote
    attacker can exploit these issues to corrupt memory and
    execute arbitrary code. (CVE-2015-4501)

  - A flaw exists that allows scripted proxies to access the
    inner window. (CVE-2015-4502)

  - An out-of-bounds read error exists in the QCMS color
    management library that is triggered when manipulating
    an image with specific attributes in its ICC V4 profile.
    A remote attacker can exploit this to cause a denial of
    service condition or to disclose sensitive information.
    (CVE-2015-4504)

  - A buffer overflow condition exists in the libvpx
    component when parsing vp9 format video. A remote
    attacker can exploit this, via a specially crafted vp9
    format video, to execute arbitrary code. (CVE-2015-4506)

  - A flaw exists in the debugger API that is triggered when
    using the debugger with SavedStacks in JavaScript. An
    attacker can exploit this to cause a denial of service
    condition. (CVE-2015-4507)

  - A flaw exists in reader mode that allows an attacker to
    spoof the URL displayed in the address bar.
    (CVE-2015-4508)

  - A user-after-free error exists when manipulating HTML
    media elements on a page during script manipulation of
    the URI table of these elements. An attacker can exploit
    this to cause a denial of service condition.
    (CVE-2015-4509)

  - A use-after-free error exists when using a shared worker
    with IndexedDB due to a race condition with the worker.
    A remote attacker can exploit this, via specially
    crafted content, to cause a denial of service condition.
    (CVE-2015-4510)

  - A security bypass vulnerability exists due to a flaw in
    Gecko's implementation of the ECMAScript 5 API. An
    attacker can exploit this to run web content in a
    privileged context, resulting in the execution of
    arbitrary code. (CVE-2015-4516)

  - A memory corruption issue exists in NetworkUtils.cpp. An
    attacker can potentially exploit this issue to cause a
    denial of service condition or to execute arbitrary
    code. (CVE-2015-4517)

  - An information disclosure vulnerability exists due to a
    flaw that occurs when a previously loaded image on a
    page is dropped into content after a redirect, resulting
    in the redirected URL being available to scripts.
    (CVE-2015-4519)

  - Multiple security bypass vulnerabilities exist due to
    errors in the handling of CORS preflight request
    headers. (CVE-2015-4520)

  - A memory corruption issue exists in the
    ConvertDialogOptions() function. An attacker can
    potentially exploit this issue to cause a denial of
    service condition or to execute arbitrary code.
    (CVE-2015-4521)

  - An overflow condition exists in the GetMaxLength()
    function. An attacker can potentially exploit this to
    cause a denial of service condition or to execute
    arbitrary code. (CVE-2015-4522)

  - An overflow condition exists in the GrowBy() function.
    An attacker can potentially exploit this to cause a
    denial of service condition or to execute arbitrary
    code. (CVE-2015-7174)

  - An overflow condition exists in the AddText() function.
    An attacker can potentially exploit this to cause a
    denial of service condition or to execute arbitrary
    code. (CVE-2015-7175)

  - A stack overflow condition exists in the
    AnimationThread() function due to a bad sscanf
    argument. An attacker can potentially exploit this to
    cause a denial of service condition or to execute
    arbitrary code. (CVE-2015-7176)

  - A memory corruption issue exists in the InitTextures()
    function. An attacker can potentially exploit this issue
    to cause a denial of service condition or to execute
    arbitrary code. (CVE-2015-7177)

  - A memory corruption issue exists in
    ReadbackResultWriterD3D11::Run due to mishandling of the
    return status. An attacker can potentially exploit this
    issue to cause a denial of service condition or to
    execute arbitrary code. (CVE-2015-7180)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-96/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-98/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-101/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-102/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-103/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-104/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-105/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-106/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-108/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-109/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-110/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-111/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-112/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 41 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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

mozilla_check_version(product:'firefox', version:version, path:path, esr:FALSE, fix:'41', severity:SECURITY_HOLE);
