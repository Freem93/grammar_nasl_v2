#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63468);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/16 13:53:27 $");

  script_cve_id(
    "CVE-2012-5145",
    "CVE-2012-5146",
    "CVE-2012-5147",
    "CVE-2012-5148",
    "CVE-2012-5149",
    "CVE-2012-5150",
    "CVE-2012-5151",
    "CVE-2012-5152",
    "CVE-2012-5153",
    "CVE-2012-5154",
    "CVE-2012-5156",
    "CVE-2012-5157",
    "CVE-2013-0630",
    "CVE-2013-0828",
    "CVE-2013-0829",
    "CVE-2013-0830",
    "CVE-2013-0831",
    "CVE-2013-0832",
    "CVE-2013-0833",
    "CVE-2013-0834",
    "CVE-2013-0835",
    "CVE-2013-0836",
    "CVE-2013-0837"
  );
  script_bugtraq_id(
    57184,
    59413,
    59414,
    59415,
    59416,
    59417,
    59418,
    59419,
    59420,
    59422,
    59423,
    59424,
    59425,
    59426,
    59427,
    59428,
    59429,
    59430,
    59431,
    59435,
    59436,
    59437,
    59438
  );
  script_osvdb_id(
    88969,
    89072,
    89073,
    89074,
    89075,
    89076,
    89077,
    89078,
    89079,
    89080,
    89081,
    89082,
    89083,
    89084,
    89085,
    89086,
    89087,
    89088,
    89089,
    89090,
    89091,
    89092,
    89093,
    89095,
    96594
  );

  script_name(english:"Google Chrome < 24.0.1312.52 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 24.0.1312.52 and is, therefore, affected by the following
vulnerabilities :

  - Use-after-free errors exist related to SVG layout,
    DOM handling, video seeking, PDF fields and printing.
    (CVE-2012-5145, CVE-2012-5147, CVE-2012-5150,
    CVE-2012-5156, CVE-2013-0832)

  - An error related to malformed URLs can allow a Same
    Origin Policy (SOP) bypass, thereby allowing cross-site
    scripting attacks. (CVE-2012-5146)

  - A user-input validation error exists related to filenames
    and hyphenation support. (CVE-2012-5148)

  - Integer overflow errors exist related to audio IPC
    handling, PDF JavaScript and shared memory allocation.
    (CVE-2012-5149, CVE-2012-5151, CVE-2012-5154)

  - Out-of-bounds read errors exist related to video
    seeking, PDF image handling, printing and glyph
    handling. (CVE-2012-5152, CVE-2012-5157,
    CVE-2012-0833, CVE-2012-0834)

  - An out-of-bounds stack access error exists in the
    v8 JavaScript engine. (CVE-2012-5153)

  - A casting error exists related to PDF 'root' handling.
    (CVE-2013-0828)

  - An unspecified error exists that can corrupt database
    metadata leading to incorrect file access.
    (CVE-2013-0829)

  - An error exists related to IPC and 'NUL' termination.
    (CVE-2013-0830)

  - An error exists related to extensions that may allow
    improper path traversals. (CVE-2013-0831)

  - An unspecified error exists related to geolocation.
    (CVE-2013-0835)

  - An unspecified error exists related to garbage
    collection in the v8 JavaScript engine. (CVE-2013-0836)

  - An unspecified error exists related to extension tab
    handling. (CVE-2013-0837)

  - The bundled version of Adobe Flash Player contains
    flaws that can lead to arbitrary code execution.
    (CVE-2013-0630)

Successful exploitation of some of these issues could lead to an
application crash or even allow arbitrary code execution, subject to the
user's privileges.");
  # http://googlechromereleases.blogspot.com/2013/01/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4ab915a3");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb13-01.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 24.0.1312.52 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/10");

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
google_chrome_check_version(installs:installs, fix:'24.0.1312.52', severity:SECURITY_HOLE, xss:TRUE);
