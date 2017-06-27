#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58644);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/16 13:53:26 $");

  script_cve_id(
    "CVE-2011-3066",
    "CVE-2011-3067",
    "CVE-2011-3068",
    "CVE-2011-3069",
    "CVE-2011-3070",
    "CVE-2011-3071",
    "CVE-2011-3072",
    "CVE-2011-3073",
    "CVE-2011-3074",
    "CVE-2011-3075",
    "CVE-2011-3076",
    "CVE-2011-3077",
    "CVE-2012-0724",
    "CVE-2012-0725"
  );
  script_bugtraq_id(52913, 57027);
  script_osvdb_id(
    81036,
    81037,
    81038,
    81039,
    81040,
    81041,
    81042,
    81043,
    81044,
    81045,
    81046,
    81047,
    81244,
    81245
  );

  script_name(english:"Google Chrome < 18.0.1025.151 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 18.0.1025.151 and is, therefore, affected by the following
vulnerabilities :

  - An out-of-bounds read issue exists related to 'Skia'
    clipping. (CVE-2011-3066)

  - An error exists related to cross-origin iframe
    replacement. (CVE-2011-3067)

  - Use-after-free errors exist related to 'run-in'
    handling, line box editing, v8 JavaScript engine
    bindings, 'HTMLMediaElement', SVG resource handling,
    media handling, style command application, and focus
    handling. (CVE-2011-3068, CVE-2011-3069, CVE-2011-3070,
    CVE-2011-3071, CVE-2011-3073, CVE-2011-3074,
    CVE-2011-3075, CVE-2011-3076)

  - A cross-origin violation error exists related to pop-up
    windows. (CVE-2011-3072)

  - A read-after-free error exists related to script
    binding. (CVE-2011-3077)

  - The bundled Adobe Flash Player is vulnerable to several
    memory corruption issues that can lead to arbitrary
    code execution. (CVE-2012-0724, CVE-2012-0725)");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?344c5385");
  # Adobe Flash Advisory
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2e04086e");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 18.0.1025.151 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/09");

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
google_chrome_check_version(installs:installs, fix:'18.0.1025.151', severity:SECURITY_HOLE);
