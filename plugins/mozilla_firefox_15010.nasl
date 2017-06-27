#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24701);
  script_version("$Revision: 1.27 $");
  script_cvs_date("$Date: 2016/11/28 21:52:56 $");

  script_cve_id(
    "CVE-2006-6077",
    "CVE-2007-0008",
    "CVE-2007-0009",
    "CVE-2007-0775",
    "CVE-2007-0776",
    "CVE-2007-0777",
    "CVE-2007-0778",
    "CVE-2007-0779",
    "CVE-2007-0780",
    "CVE-2007-0800",
    "CVE-2007-0801",
    "CVE-2007-0802",
    "CVE-2007-0981",
    "CVE-2007-0994",
    "CVE-2007-0995",
    "CVE-2007-0996",
    "CVE-2007-1092"
  );
  script_bugtraq_id(21240, 22396, 22566, 22679, 22694, 22826);
  script_osvdb_id(
    30641,
    32103,
    32104,
    32105,
    32106,
    32107,
    32108,
    32109,
    32110,
    32111,
    32112,
    32113,
    32114,
    32115,
    33705,
    33811,
    33812,
    79165
  );

  script_name(english:"Firefox < 1.5.0.10 / 2.0.0.2 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Firefox is affected by various security
issues, some of which could lead to execution of arbitrary code on the
affected host subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-01.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-02.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-03.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-04.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-05.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-06.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-07.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-08.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-09.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 1.5.0.10 / 2.0.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79, 119, 189, 264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");

ver = read_version_in_kb("Mozilla/Firefox/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 1 ||
  (
    ver[0] == 1 &&
    (
      ver[1] < 5 ||
      (ver[1] == 5 && ver[2] == 0 && ver[3] < 10)
    )
  ) ||
  (ver[0] == 2 && ver[1] == 0 && ver[2] == 0 && ver[3] < 2)
) security_hole(get_kb_item("SMB/transport"));
