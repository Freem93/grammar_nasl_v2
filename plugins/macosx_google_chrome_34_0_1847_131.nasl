#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73711);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/28 21:06:38 $");

  script_cve_id(
    "CVE-2014-0515",
    "CVE-2014-1730",
    "CVE-2014-1731",
    "CVE-2014-1732",
    "CVE-2014-1733",
    "CVE-2014-1734",
    "CVE-2014-1735",
    "CVE-2014-1736"
  );
  script_bugtraq_id(67082, 67092);
  script_osvdb_id(
    105745,
    105749,
    106336,
    106337,
    106338,
    106339,
    106340,
    106341,
    106342,
    106347
  );

  script_name(english:"Google Chrome < 34.0.1847.131 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Mac OS X host is
a version prior to 34.0.1847.131. It is, therefore, affected by the
following vulnerabilities :

  - A buffer overflow error exists related to the included
    version of Flash Player. (CVE-2014-0515)

  - Type confusion errors exist related to the V8
    JavaScript engine and DOM handling. (CVE-2014-1730,
    CVE-2014-1731)

  - A use-after-free error exists related to speech
    recognition processing. (CVE-2014-1732)

  - An error exists related to compiling in 'Seccomp-BPF'.
    (CVE-2014-1733)

  - Various, unspecified errors exist. (CVE-2014-1734)

  - Various, unspecified errors exist related to the V8
    JavaScript engine. (CVE-2014-1735)

  - An integer overflow error exists related to the V8
    JavaScript engine. (CVE-2014-1736)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://googlechromereleases.blogspot.com/2014/04/stable-channel-update_24.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b5291952");
  script_set_attribute(attribute:"see_also", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-13.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 34.0.1847.131 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player Shader Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'34.0.1847.131', severity:SECURITY_WARNING);
