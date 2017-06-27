#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65691);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/10/03 03:33:27 $");

  script_cve_id(
    "CVE-2013-0916",
    "CVE-2013-0917",
    "CVE-2013-0918",
    "CVE-2013-0920",
    "CVE-2013-0921",
    "CVE-2013-0922",
    "CVE-2013-0923",
    "CVE-2013-0924",
    "CVE-2013-0925",
    "CVE-2013-0926"
  );
  script_bugtraq_id(
    58723,
    58724,
    58725,
    58728,
    58729,
    58730,
    58731,
    58732,
    58733,
    58734
  );
  script_osvdb_id(
    91701,
    91703,
    91704,
    91705,
    91706,
    91707,
    91708,
    91709,
    91710,
    91711
  );

  script_name(english:"Google Chrome < 26.0.1410.43 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is a
version prior to 26.0.1410.43 and is, therefore, affected by the
following vulnerabilities :

  - Use-after-free errors exist related to 'Web Audio' and
    the extension bookmarks API. (CVE-2013-0916,
    CVE-2013-0920)

  - An out-of-bounds read error exists related to the URL
    loader. (CVE-2013-0917)

  - An unspecified error exists related to 'drag and drop'
    actions and the developer tools. (CVE-2013-0918)

  - An unspecified error exists related to website process
    isolation. (CVE-2013-0921)

  - An error exists related to HTTP basic authentication
    and brute-force attacks. (CVE-2013-0922)

  - A memory safety issue exists related to the 'USB Apps'
    API. (CVE-2013-0923)

  - A permissions error exists related to extensions API
    and file permissions. (CVE-2013-0924)

  - URLs can be leaked to extensions even if the extension
    does not have the 'tabs' permission. (CVE-2013-0925)

  - An error exists related to 'active tags' and the paste
    action that has unspecified impact. (CVE-2013-0926)");
  # http://googlechromereleases.blogspot.com/2013/03/stable-channel-update_26.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?11700993");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 26.0.1410.43 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'26.0.1410.43', severity:SECURITY_WARNING);
