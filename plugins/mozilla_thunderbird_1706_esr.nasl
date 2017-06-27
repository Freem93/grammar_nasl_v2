#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66482);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/16 14:12:51 $");

  script_cve_id(
    "CVE-2013-0801",
    "CVE-2013-1670",
    "CVE-2013-1672",
    "CVE-2013-1674",
    "CVE-2013-1675",
    "CVE-2013-1676",
    "CVE-2013-1677",
    "CVE-2013-1678",
    "CVE-2013-1679",
    "CVE-2013-1680",
    "CVE-2013-1681"
  );
  script_bugtraq_id(
    59855,
    59858,
    59859,
    59860,
    59861,
    59862,
    59863,
    59864,
    59865,
    59868,
    59872
  );
  script_osvdb_id(
    93422,
    93423,
    93424,
    93425,
    93427,
    93429,
    93430,
    93431,
    93432,
    93433,
    93434
  );

  script_name(english:"Mozilla Thunderbird ESR 17.x < 17.0.6 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Thunderbird ESR");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains a mail client that is potentially
affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of Thunderbird ESR 17.x is earlier than 17.0.6
and is, therefore, potentially affected the following vulnerabilities:

  - Various memory safety issues exist. (CVE-2013-0801)

  - It is possible to call a content level constructor that
    allows for the constructor to have chrome privileged
    access. (CVE-2013-1670)

  - A local privilege escalation issues exists in the
    Mozilla Maintenance Service. (CVE-2013-1672)

  - A use-after-free vulnerability exists when resizing
    video while playing. (CVE-2013-1674)

  - Some 'DOMSVGZoomEvent' functions are used without being
    properly initialized, which could lead to information
    disclosure. (CVE-2013-1675)

  - Multiple memory corruption issues exist. (CVE-2013-1676,
    CVE-2013-1677, CVE-2013-1678, CVE-2013-1679,
    CVE-2013-1680, CVE-2013-1681)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-41.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-42.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-44.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-46.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-47.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-48.html");

  script_set_attribute(attribute:"solution", value:"Upgrade to Thunderbird ESR 17.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/16");

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

port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:TRUE, fix:'17.0.6', min:'17.0', severity:SECURITY_HOLE);
