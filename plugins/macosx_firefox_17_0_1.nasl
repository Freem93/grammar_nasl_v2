#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63543);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/05/16 19:43:13 $");

  script_cve_id(
    "CVE-2013-0749",
    "CVE-2013-0761",
    "CVE-2013-0762",
    "CVE-2013-0763",
    "CVE-2013-0766",
    "CVE-2013-0767",
    "CVE-2013-0769",
    "CVE-2013-0771"
  );
  script_bugtraq_id(
    57193,
    57194,
    57195,
    57196,
    57197,
    57198,
    57203,
    57205
  );
  script_osvdb_id(
    88997,
    88998,
    89001,
    89002,
    89003,
    89004,
    89005,
    89006
  );

  script_name(english:"Firefox < 17.0.1 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of Firefox is earlier than 17.0.1 and thus, is
potentially affected by the following security issues :

  - An unspecified memory corruption issue exists.
    (CVE-2013-0749, CVE-2013-0769)

  - Multiple, unspecified use-after-free, out-of-bounds read
    and buffer overflow errors exist. (CVE-2013-0761,
    CVE-2013-0762, CVE-2013-0763, CVE-2013-0766,
    CVE-2013-0767, CVE-2013-0771)"
  );
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-01/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-02/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 17.0.1 / 17.0.1 ESR or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Installed");

  exit(0);
}

include("mozilla_version.inc");
kb_base = "MacOSX/Firefox";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

mozilla_check_version(product:'firefox', version:version, path:path, esr:FALSE, fix:'17.0.1', severity:SECURITY_HOLE);