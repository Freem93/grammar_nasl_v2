#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88460);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/28 18:52:11 $");

  script_cve_id(
    "CVE-2016-1930",
    "CVE-2016-1935"
  );
  script_osvdb_id(
    133631,
    133641,
    133642,
    133643,
    133644,
    133645,
    133646,
    133647,
    133648,
    133649,
    133651,
    133652,
    133654
  );
  script_xref(name:"MFSA", value:"2016-01");
  script_xref(name:"MFSA", value:"2016-03");

  script_name(english:"Firefox ESR < 38.6 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote Windows host is
prior to 38.6. It is, therefore, affected by the following
vulnerabilities :

  - Multiple unspecified memory corruption issues exist that
    allow a remote attacker to execute arbitrary code.
    (CVE-2016-1930)

  - A buffer overflow condition exists in WebGL that is
    triggered when handling cache out-of-memory error
    conditions. A remote attacker can exploit this to
    execute arbitrary code. (CVE-2016-1935)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-01/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-03/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox ESR version 38.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'38.6', severity:SECURITY_HOLE);
