#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94958);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/05 16:04:17 $");

  script_cve_id(
    "CVE-2016-5289",
    "CVE-2016-5290",
    "CVE-2016-5291",
    "CVE-2016-5292",
    "CVE-2016-5296",
    "CVE-2016-5297",
    "CVE-2016-9063",
    "CVE-2016-9064",
    "CVE-2016-9066",
    "CVE-2016-9067",
    "CVE-2016-9068",
    "CVE-2016-9069",
    "CVE-2016-9070",
    "CVE-2016-9071",
    "CVE-2016-9073",
    "CVE-2016-9074",
    "CVE-2016-9075",
    "CVE-2016-9076",
    "CVE-2016-9077"
  );
  script_bugtraq_id(
    94335,
    94336,
    94337,
    94339,
    94341
  );
  script_osvdb_id(
    147338,
    147339,
    147342,
    147343,
    147345,
    147346,
    147347,
    147348,
    147350,
    147351,
    147352,
    147360,
    147361,
    147362,
    147363,
    147364,
    147365,
    147366,
    147367,
    147368,
    147369,
    147370,
    147371,
    147372,
    147373,
    147374,
    147375,
    147376,
    147377,
    147378,
    147379,
    147380,
    147381,
    147382,
    147383,
    147384,
    147385,
    147386,
    147387
  );
  script_xref(name:"MFSA", value:"2016-89");

  script_name(english:"Mozilla Firefox < 50.0 Multiple Vulnerabilities (macOS)");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote macOS or Mac OS X host contains a web browser that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox installed on the remote macOS or Mac
OS X host is prior to 50.0. It is, therefore, affected by multiple
vulnerabilities, the majority of which are remote code execution
vulnerabilities. An unauthenticated, remote attacker can exploit these
vulnerabilities by convincing a user to visit a specially crafted
website, resulting in the execution of arbitrary code in the context
of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-89/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 50.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/18");

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

mozilla_check_version(product:'firefox', version:version, path:path, esr:FALSE, fix:'50', severity:SECURITY_HOLE);
