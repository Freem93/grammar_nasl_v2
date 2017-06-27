#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57876);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/20 14:03:00 $");

  script_cve_id(
    "CVE-2011-3953",
    "CVE-2011-3954",
    "CVE-2011-3955",
    "CVE-2011-3956",
    "CVE-2011-3957",
    "CVE-2011-3958",
    "CVE-2011-3959",
    "CVE-2011-3960",
    "CVE-2011-3961",
    "CVE-2011-3962",
    "CVE-2011-3963",
    "CVE-2011-3964",
    "CVE-2011-3965",
    "CVE-2011-3966",
    "CVE-2011-3967",
    "CVE-2011-3968",
    "CVE-2011-3969",
    "CVE-2011-3970",
    "CVE-2011-3971",
    "CVE-2011-3972"
  );
  script_bugtraq_id(51911);
  script_osvdb_id(
    77698,
    78933,
    78934,
    78935,
    78936,
    78937,
    78938,
    78940,
    78941,
    78942,
    78943,
    78944,
    78945,
    78946,
    78947,
    78948,
    78949,
    78950,
    78951,
    78952
  );

  script_name(english:"Google Chrome < 17.0.963.46 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 17.0.963.46 and is, therefore, affected by the following
vulnerabilities:

  - Clipboard monitoring after a paste action is possible.
    (CVE-2011-3953)

  - Application crashes are possible with excessive
    database usage, killing an 'IndexDB' transaction,
    signature checks and processing unusual certificates.
    (CVE-2011-3954, CVE-2011-3955, CVE-2011-3965,
    CVE-2011-3967)

  - Sandboxed origins are not handled properly inside
    extensions. (CVE-2011-3956)

  - Use-after-free errors exist related to PDF garbage
    collection, stylesheet error handling, CSS handling,
    SVG layout and 'mousemove' event handling.
    (CVE-2011-3957, CVE-2011-3966, CVE-2011-3968,
     CVE-2011-3969, CVE-2011-3971)

  - An error exists related to bad casting and column
    spans. (CVE-2011-3958)

  - A buffer overflow exists related to locale handing.
    (CVE-2011-3959)

  - Out-of-bounds read errors exist related to audio
    decoding, path clipping, PDF fax imaging, 'libxslt',
    and the shader translator. (CVE-2011-3960,
    CVE-2011-3962, CVE-2011-3963, CVE-2011-3970,
    CVE-2011-3972)

  - A race condition exists after a utility process
    crashes. (CVE-2011-3961)

  - An unspecified error exists related to the URL bar
    after drag and drop operations. (CVE-2011-3964)");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?301ce561");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 17.0.963.46 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/09");

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
google_chrome_check_version(installs:installs, fix:'17.0.963.46', severity:SECURITY_HOLE);
