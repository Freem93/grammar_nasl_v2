#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71348);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/20 14:12:06 $");

  script_cve_id(
    "CVE-2013-5609",
    "CVE-2013-5610",
    "CVE-2013-5613",
    "CVE-2013-5615",
    "CVE-2013-5616",
    "CVE-2013-5618",
    "CVE-2013-6629",
    "CVE-2013-6630",
    "CVE-2013-6671",
    "CVE-2013-6673"
  );
  script_bugtraq_id(
    63676,
    63679,
    64203,
    64204,
    64206,
    64209,
    64211,
    64212,
    64213,
    64216
  );
  script_osvdb_id(
    99710,
    99711,
    100806,
    100807,
    100808,
    100812,
    100813,
    100815,
    100816,
    100818
  );

  script_name(english:"Mozilla Thunderbird < 24.2 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains a mail client that is potentially
affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of Thunderbird is earlier than 24.2 and is,
therefore, potentially affected the following vulnerabilities:

  - Memory issues exist in the browser engine that could
    result in a denial of service or arbitrary code
    execution. (CVE-2013-5609, CVE-2013-5610)

  - Two use-after-free vulnerabilities exist in the
    functions for synthetic mouse movement handling.
    (CVE-2013-5613)

  - An issue exists in which 'GetElementIC' typed array
    stubs can be generated outside observed typesets. This
    could lead to unpredictable behavior with a potential
    security impact. (CVE-2013-5615)

  - A use-after-free vulnerability exists when
    interacting with event listeners from the mListeners
    array.  This could result in a denial of service or
    arbitrary code execution. (CVE-2013-5616)

  - A use-after-free vulnerability exists in the table
    editing user interface of the editor during garbage
    collection.  This could result in a denial of service or
    arbitrary code execution. (CVE-2013-5618)

  - Issues exist with the JPEG format image processing with
    Start Of Scan (SOS) and Define Huffman Table (DHT)
    markers in the 'libjpeg' library.  This could allow
    attackers to read arbitrary memory content as well as
    cross-domain image theft. (CVE-2013-6629, CVE-2013-6630)

  - A memory issue exists when inserting an ordered list
    into a document through a script that could result in a
    denial of service or arbitrary code execution.
    (CVE-2013-6671)

  - Trust settings for built-in root certificates are
    ignored during extended validation (EV) certificate
    validation.  This removes the ability of users to
    explicitly untrust root certificates from specific
    certificate authorities. (CVE-2013-6673)

  - An intermediate certificate that is used by a man-in-
    the-middle (MITM) traffic management device exists in
    Mozilla's root certificate authorities.  Reportedly,
    this certificate has been misused."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-104.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-108.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-109.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-111.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-113.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-114.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-115.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-116.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-117.html");

  script_set_attribute(attribute:"solution", value:"Upgrade to Thunderbird 24.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");
  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'24.2', severity:SECURITY_HOLE, xss:FALSE);
