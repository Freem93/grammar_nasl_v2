#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93315);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/11 20:19:26 $");

  script_cve_id(
    "CVE-2016-5147",
    "CVE-2016-5148",
    "CVE-2016-5149",
    "CVE-2016-5150",
    "CVE-2016-5151",
    "CVE-2016-5152",
    "CVE-2016-5153",
    "CVE-2016-5154",
    "CVE-2016-5155",
    "CVE-2016-5156",
    "CVE-2016-5157",
    "CVE-2016-5158",
    "CVE-2016-5159",
    "CVE-2016-5160",
    "CVE-2016-5161",
    "CVE-2016-5162",
    "CVE-2016-5163",
    "CVE-2016-5164",
    "CVE-2016-5165",
    "CVE-2016-5166",
    "CVE-2016-5167"
  );
  script_osvdb_id(
    143642,
    143643,
    143644,
    143645,
    143646,
    143647,
    143648,
    143649,
    143650,
    143651,
    143652,
    143653,
    143654,
    143655,
    143656,
    143657,
    143658,
    143659,
    143688,
    143718,
    143720,
    143723,
    143724,
    143726,
    143727,
    143737,
    143744,
    143746,
    143747,
    143752
  );

  script_name(english:"Google Chrome < 53.0.2785.89 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is
prior to 53.0.2785.89. It is, therefore, affected by multiple
vulnerabilities :

  - Universal XSS in Blink. Credit to anonymous

  - Universal XSS in Blink. Credit to anonymous

  - Script injection in extensions. Credit to Max Justicz
    (http

  - Use after free in Blink. Credit to anonymous

  - Use after free in PDFium. Credit to anonymous

  - Heap overflow in PDFium. Credit to GiWan Go of Stealien

  - Use after destruction in Blink. Credit to Atte Kettunen
    of OUSPG

  - Heap overflow in PDFium. Credit to anonymous

  - Address bar spoofing. Credit to anonymous

  - Use after free in event bindings. Credit to jinmo123

  - Heap overflow in PDFium. Credit to anonymous

  - Heap overflow in PDFium. Credit to GiWan Go of Stealien

  - Heap overflow in PDFium. Credit to GiWan Go of Stealien

  - Type confusion in Blink. Credit to
    62600BCA031B9EB5CB4A74ADDDD6771E working with Trend
    Micro's Zero Day Initiative

  - Extensions web accessible resources bypass. Credit to
    Nicolas Golubovic

  - Address bar spoofing. Credit to Rafay Baloch PTCL
    Etisalat (http

  - Universal XSS using DevTools. Credit to anonymous

  - Script injection in DevTools. Credit to Gregory
    Panakkal

  - SMB Relay Attack via Save Page As. Credit to Gregory
    Panakkal

  - Extensions web accessible resources bypass. Credit to
    @l33terally, FogMarks.com (@FogMarks)

  - Various fixes from internal audits, fuzzing and other
    initiatives.

Note that Nessus has not tested for these issues but has instead
relied only on the applications self-reported version number.

Note that Tenable Network Security has extracted the preceding
description block directly from the Chrome security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # http://googlechromereleases.blogspot.com/2016/08/stable-channel-update-for-desktop_31.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?f6e7512a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version to 53.0.2785.89 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/02");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");
installs = get_kb_list("SMB/Google_Chrome/*");

google_chrome_check_version(installs:installs, fix:'53.0.2785.89', severity:SECURITY_HOLE);
