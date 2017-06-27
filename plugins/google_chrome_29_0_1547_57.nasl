#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69423);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/16 13:53:27 $");

  script_cve_id(
    "CVE-2013-2887",
    "CVE-2013-2900",
    "CVE-2013-2901",
    "CVE-2013-2902",
    "CVE-2013-2903",
    "CVE-2013-2904",
    "CVE-2013-2905",
    "CVE-2013-6166"
  );
  script_bugtraq_id(
    58857,
    61885,
    61886,
    61887,
    61888,
    61889,
    61890,
    61891
  );
  script_osvdb_id(
    96201,
    96431,
    96432,
    96433,
    96434,
    96435,
    96440,
    96441,
    96442,
    96443,
    96444,
    96445,
    96447,
    96466,
    96467,
    96468,
    96469,
    96470,
    96471,
    96472,
    98762
  );

  script_name(english:"Google Chrome < 29.0.1547.57 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is a version
prior to 29.0.1547.57.  It is, therefore, affected by multiple
vulnerabilities :

  - Various unspecified errors exist. No further details
    have been provided. (CVE-2013-2887)

  - An input validation error exists related to incomplete
    paths and file handling. (CVE-2013-2900)

  - An integer overflow error exists related to 'ANGLE'.
    (CVE-2013-2901)

  - Use-after-free errors exist related to 'XSLT', the
    'media' element and document parsing. (CVE-2013-2902,
    CVE-2013-2903, CVE-2013-2904)

  - An error exists related to shared memory files that
    could lead to the disclosure of sensitive information.
    (CVE-2013-2905)

  - An error exists related to HTTP Cookie headers and
    validation that could allow denial of service attacks.
    (CVE-2013-6166)"
  );
  # http://googlechromereleases.blogspot.com/2013/08/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?51dcd991");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2013/q4/121");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 29.0.1547.57 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'29.0.1547.57', severity:SECURITY_WARNING);
