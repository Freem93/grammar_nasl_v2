#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63232);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/09/29 20:31:25 $");

  script_cve_id(
    "CVE-2012-5139",
    "CVE-2012-5140",
    "CVE-2012-5141",
    "CVE-2012-5142",
    "CVE-2012-5143",
    "CVE-2012-5144",
    "CVE-2012-5676",
    "CVE-2012-5677",
    "CVE-2012-5678"
  );
  script_bugtraq_id(56892, 56896, 56898, 56903);
  script_osvdb_id(
    88353,
    88354,
    88356,
    88372,
    88373,
    88374,
    88375,
    88376,
    88377,
    88734
  );

  script_name(english:"Google Chrome < 23.0.1271.97 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 23.0.1271.97 and is, therefore, affected by the following
vulnerabilities :

  - Use-after-free errors exist related to visibility events
    and the URL loader. (CVE-2012-5139, CVE-2012-5140)

  - An unspecified error exists related to instantiation
    of the 'Chromoting' client plugin. (CVE-2012-5141)

  - An unspecified error exists related to history
    navigation that can lead to application crashes.
    (CVE-2012-5142)

  - An integer overflow error exists related to the 'PPAPI'
    image buffers. (CVE-2012-5143)

  - A stack corruption error exists related to 'AAC'
    decoding. (CVE-2012-5144)

  - The bundled version of Adobe Flash Player contains
    flaws that can lead to arbitrary code execution.
    (CVE-2012-5676, CVE-2012-5677, CVE-2012-5678)

Successful exploitation of some of these issues could lead to an
application crash or even allow arbitrary code execution, subject to the
user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-021/");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-27.html");
  # http://googlechromereleases.blogspot.com/2012/12/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d48bc855");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 23.0.1271.97 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'23.0.1271.97', severity:SECURITY_HOLE);
