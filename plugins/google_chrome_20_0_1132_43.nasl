#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59735);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/10/10 15:57:06 $");

  script_cve_id(
    "CVE-2012-2764",
    "CVE-2012-2815",
    "CVE-2012-2816",
    "CVE-2012-2817",
    "CVE-2012-2818",
    "CVE-2012-2819",
    "CVE-2012-2820",
    "CVE-2012-2821",
    "CVE-2012-2822",
    "CVE-2012-2823",
    "CVE-2012-2824",
    "CVE-2012-2825",
    "CVE-2012-2826",
    "CVE-2012-2828",
    "CVE-2012-2829",
    "CVE-2012-2830",
    "CVE-2012-2831",
    "CVE-2012-2832",
    "CVE-2012-2833",
    "CVE-2012-2834"
  );
  script_bugtraq_id(54203, 54477);
  script_osvdb_id(
    83237,
    83238,
    83240,
    83241,
    83242,
    83243,
    83244,
    83245,
    83246,
    83247,
    83248,
    83249,
    83250,
    83251,
    83252,
    83253,
    83254,
    83255,
    83256,
    83257
  );

  script_name(english:"Google Chrome < 20.0.1132.43 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 20.0.1132.43 and is, therefore, affected by the following
vulnerabilities :

  - An error exists related to the loading of the 'metro'
    DLL. (CVE-2012-2764)

  - An error exists related to the leaking of iframe
    fragment id. (CVE-2012-2815)

  - An error exists that allows sandboxes to interfere with
    each other. (CVE-2012-2816)

  - Multiple use-after-free errors exist related to table
    section handling, counter layout, SVG resource handling,
    SVG painting, first-letter handling and SVG reference
    handling. (CVE-2012-2817, CVE-2012-2818, CVE-2012-2823,
    CVE-2012-2824, CVE-2012-2829, CVE-2012-2831)

  - An error exists related to texture handling that can
    cause application crashes. (CVE-2012-2819)

  - Out-of-bounds read errors exist related to SVG
    filter handling and texture conversion. (CVE-2012-2820,
    CVE-2012-2826)

  - An unspecified error exists related to autofill display
    actions. (CVE-2012-2821)

  - Several 'OOB' read issues exist related to PDF
    processing. (CVE-2012-2822)

  - A read error exists related to XSL handling.
    (CVE-2012-2825)

  - Several integer overflow issues exist related to PDF
    processing. (CVE-2012-2828)

  - A pointer issue exists related to the setting of array
    values. (CVE-2012-2830)

  - An uninitialized pointer issue exists related to the
    PDF image codec. (CVE-2012-2832)

  - A buffer overflow error exists related to the PDF
    JavaScript API. (CVE-2012-2833)

  - An integer overflow error exists related to the
    'Matroska' container. (CVE-2012-2834)");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Jul/93");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c9fd4072");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 20.0.1132.43 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'20.0.1132.43', severity:SECURITY_HOLE);
