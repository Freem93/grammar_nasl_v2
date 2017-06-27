#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88089);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/20 14:12:05 $");

  script_cve_id(
    "CVE-2016-1612",
    "CVE-2016-1613",
    "CVE-2016-1614",
    "CVE-2016-1615",
    "CVE-2016-1616",
    "CVE-2016-1617",
    "CVE-2016-1618",
    "CVE-2016-1619",
    "CVE-2016-1620"
  );
  script_osvdb_id(
    131529,
    132005,
    133436,
    133437,
    133438,
    133439,
    133440,
    133441,
    133442,
    133443,
    133444,
    133445,
    133446,
    133447,
    133448,
    133449,
    133450,
    133488,
    133489,
    133490,
    133495,
    133496,
    133507,
    133521,
    133536,
    133537,
    133538,
    133539,
    133540,
    133541,
    133542,
    133543,
    133544
  );

  script_name(english:"Google Chrome < 48.0.2564.82 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version number of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Mac OS X host is
prior to 48.0.2564.82. It is, therefore, affected by multiple
vulnerabilities :

  - A unspecified vulnerability exists in Google V8 when
    handling compatible receiver checks hidden behind
    receptors. An attacker can exploit this to have an
    unspecified impact. No other details are available.
    (CVE-2016-1612)

  - A user-after-free error exists in PDFium due to improper
    invalidation of IPWL_FocusHandler and IPWL_Provider upon
    destruction. An attacker can exploit this to deference
    already freed memory, resulting in the execution of
    arbitrary code. (CVE-2016-1613)

  - An unspecified vulnerability exists in Blink that is
    related to the handling of bitmaps. An attacker can
    exploit this to access sensitive information. No other
    details are available. (CVE-2016-1614)

  - An unspecified vulnerability exists in omnibox that is
    related to origin confusion. An attacker can exploit
    this to have an unspecified impact. No other details are
    available. (CVE-2016-1615)

  - An unspecified vulnerability exists that allows an
    attacker to spoof a displayed URL. No other details are
    available. (CVE-2016-1616)

  - An unspecified vulnerability exists that is related to
    history sniffing with HSTS and CSP. No other details
    are available. (CVE-2016-1617)

  - A flaw exists in Blink due to the weak generation of
    random numbers by the ARC4-based random number
    generator. An attacker can exploit this to gain
    access to sensitive information. No other details are
    available. (CVE-2016-1618)

  - A out-of-bounds read error exists in PDFium in file
    fx_codec_jpx_opj.cpp in the sycc4{22,44}_to_rgb()
    functions. An attacker can exploit this to cause a
    denial of service by crashing the application linked
    using the library. (CVE-2016-1619)

  - Multiple vulnerabilities exist, the most serious of
    which allow an attacker to execute arbitrary code via a
    crafted web page. (CVE-2016-1620)");
  # http://googlechromereleases.blogspot.com/2016/01/stable-channel-update_20.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?7f4ae8d4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 48.0.2564.82 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/22");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'48.0.2564.82', severity:SECURITY_HOLE);
