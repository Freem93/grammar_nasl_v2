#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86070);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/16 14:12:50 $");

  script_cve_id(
    "CVE-2015-4500",
    "CVE-2015-4501",
    "CVE-2015-4505",
    "CVE-2015-4506",
    "CVE-2015-4509",
    "CVE-2015-4511",
    "CVE-2015-4517",
    "CVE-2015-4519",
    "CVE-2015-4520",
    "CVE-2015-4521",
    "CVE-2015-4522",
    "CVE-2015-7174",
    "CVE-2015-7175",
    "CVE-2015-7176",
    "CVE-2015-7177",
    "CVE-2015-7178",
    "CVE-2015-7179",
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
    127887,
    127890,
    127892,
    127916,
    127917,
    127918,
    127919,
    127920,
    127921,
    127922,
    127924,
    127925,
    127926
  );

  script_name(english:"Firefox ESR < 38.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote Windows host is
prior to 38.3. It is, therefore, affected by the following
vulnerabilities :

  - Multiple unspecified memory corruption issues exist due
    to improper validation of user-supplied input. A remote
    attacker can exploit these issues to corrupt memory and
    execute arbitrary code. (CVE-2015-4500)

  - Multiple unspecified memory corruption issues exist due
    to improper validation of user-supplied input. A remote
    attacker can exploit these issues to corrupt memory and
    execute arbitrary code. (CVE-2015-4501)

  - A flaw exists in the Mozilla updater that allows a local
    attacker to replace arbitrary files on the system,
    resulting in the execution of arbitrary code.
    (CVE-2015-4505)

  - A buffer overflow condition exists in the libvpx
    component when parsing vp9 format video. A remote
    attacker can exploit this, via a specially crafted vp9
    format video, to execute arbitrary code. (CVE-2015-4506)

  - A user-after-free error exists when manipulating HTML
    media elements on a page during script manipulation of
    the URI table of these elements. An attacker can exploit
    this to cause a denial of service condition.
    (CVE-2015-4509)

  - A buffer overflow condition exists in the nestegg
    library when decoding a WebM format video with
    maliciously formatted headers. An attacker can exploit
    this to cause a denial of service condition or the
    execution of arbitrary code. (CVE-2015-4511)

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

  - An out-of-bounds memory error exists in the
    linkAttributes() function when manipulating shaders. An
    attacker can potentially exploit this issue to cause a
    denial of service condition or to execute arbitrary
    code. (CVE-2015-7178)

  - An overflow condition exists in the reserveVertexSpace()
    function due to an insufficient allocation of memory for
    a shader attribute array. An attacker can potentially
    exploit this issue to cause a denial of service
    condition or to execute arbitrary code. (CVE-2015-7179)

  - A memory corruption issue exists in
    ReadbackResultWriterD3D11::Run due to mishandling of the
    return status. An attacker can potentially exploit this
    issue to cause a denial of service condition or to
    execute arbitrary code. (CVE-2015-7180)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-96/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-100/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-101/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-105/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-106/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-110/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-111/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-112/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-113/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox ESR 38.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
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

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'38.3', severity:SECURITY_HOLE);
