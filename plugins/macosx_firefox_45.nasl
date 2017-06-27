#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89873);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/20 14:12:04 $");

  script_cve_id(
     "CVE-2016-1950",
    "CVE-2016-1952",
    "CVE-2016-1953",
    "CVE-2016-1954",
    "CVE-2016-1955",
    "CVE-2016-1956",
    "CVE-2016-1957",
    "CVE-2016-1958",
    "CVE-2016-1959",
    "CVE-2016-1960",
    "CVE-2016-1961",
    "CVE-2016-1962",
    "CVE-2016-1963",
    "CVE-2016-1964",
    "CVE-2016-1965",
    "CVE-2016-1966",
    "CVE-2016-1967",
    "CVE-2016-1968",
    "CVE-2016-1969",
    "CVE-2016-1970",
    "CVE-2016-1971",
    "CVE-2016-1972",
    "CVE-2016-1973",
    "CVE-2016-1974",
    "CVE-2016-1975",
    "CVE-2016-1976",
    "CVE-2016-1977",
    "CVE-2016-1979",
    "CVE-2016-2790",
    "CVE-2016-2791",
    "CVE-2016-2792",
    "CVE-2016-2793",
    "CVE-2016-2794",
    "CVE-2016-2795",
    "CVE-2016-2796",
    "CVE-2016-2797",
    "CVE-2016-2798",
    "CVE-2016-2799",
    "CVE-2016-2800",
    "CVE-2016-2801",
    "CVE-2016-2802"
  );
  script_osvdb_id(
    135550,
    135551,
    135552,
    135553,
    135554,
    135555,
    135556,
    135557,
    135558,
    135559,
    135560,
    135561,
    135562,
    135563,
    135564,
    135565,
    135566,
    135567,
    135568,
    135569,
    135570,
    135571,
    135572,
    135573,
    135574,
    135575,
    135576,
    135577,
    135578,
    135579,
    135580,
    135581,
    135582,
    135583,
    135584,
    135585,
    135591,
    135592,
    135593,
    135594,
    135595,
    135596,
    135597,
    135598,
    135599,
    135600,
    135601,
    135602,
    135603,
    135604,
    135605,
    135606,
    135607,
    135608,
    135609,
    135610,
    135611,
    135612,
    135613,
    135614,
    135615,
    135616,
    135617,
    135618,
    135666
  );
  script_xref(name:"MFSA", value:"2016-16");
  script_xref(name:"MFSA", value:"2016-17");
  script_xref(name:"MFSA", value:"2016-18");
  script_xref(name:"MFSA", value:"2016-19");
  script_xref(name:"MFSA", value:"2016-20");
  script_xref(name:"MFSA", value:"2016-21");
  script_xref(name:"MFSA", value:"2016-22");
  script_xref(name:"MFSA", value:"2016-23");
  script_xref(name:"MFSA", value:"2016-24");
  script_xref(name:"MFSA", value:"2016-25");
  script_xref(name:"MFSA", value:"2016-26");
  script_xref(name:"MFSA", value:"2016-27");
  script_xref(name:"MFSA", value:"2016-28");
  script_xref(name:"MFSA", value:"2016-29");
  script_xref(name:"MFSA", value:"2016-30");
  script_xref(name:"MFSA", value:"2016-31");
  script_xref(name:"MFSA", value:"2016-32");
  script_xref(name:"MFSA", value:"2016-33");
  script_xref(name:"MFSA", value:"2016-34");
  script_xref(name:"MFSA", value:"2016-35");
  script_xref(name:"MFSA", value:"2016-36");
  script_xref(name:"MFSA", value:"2016-37");
  script_xref(name:"MFSA", value:"2016-38");

  script_name(english:"Firefox < 45 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Mac OS X host is prior
to 45. It is, therefore, affected by multiple vulnerabilities, the
majority of which are remote code execution vulnerabilities. An
unauthenticated, remote attacker can exploit these issues by
convincing a user to visit a specially crafted website, resulting in
the execution of arbitrary code in the context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-16/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-17/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-18/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-19/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-20/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-21/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-22/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-23/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-24/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-25/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-26/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-27/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-28/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-29/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-30/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-31/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-32/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-33/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-34/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-35/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-36/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-37/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-38/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox version 45 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

mozilla_check_version(product:'firefox', version:version, path:path, esr:FALSE, fix:'45', severity:SECURITY_HOLE);
