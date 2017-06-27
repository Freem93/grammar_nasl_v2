#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94231);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/28 21:06:37 $");

  script_cve_id("CVE-2016-5287", "CVE-2016-5288");
  script_bugtraq_id(93810, 93811);
  script_osvdb_id(146120, 146121);
  script_xref(name:"MFSA", value:"2016-87");

  script_name(english:"Mozilla Firefox 48.x / 49.x < 49.0.2 Multiple Vulnerabilities (macOS)");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote macOS host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox installed on the remote macOS host is
48.x or 49.x prior to 49.0.2. It is, therefore, affected by multiple
vulnerabilities :

  - A use-after-free error exists in the
    nsTArray_base<T>::SwapArrayElements() function during
    actor destruction with service workers. An
    unauthenticated, remote attacker can exploit this to
    dereference already freed memory, resulting in the
    execution of arbitrary code. Note that this
    vulnerability only affects version 49.x prior to
    49.0.2. (CVE-2016-5287)

  - An information disclosure vulnerability exists due to an
    unspecified flaw when e10s is disabled. An
    unauthenticated, remote attacker can exploit this, via
    specially crafted web content, to disclose sensitive
    information in the HTTP cache regarding visited URLs and
    their content. Note that this vulnerability only affects
    version 48.x or 49.x prior to 49.0.2. (CVE-2016-5288)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-87/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 49.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Installed");

  exit(0);
}

include("mozilla_version.inc");

kb_base = "MacOSX/Firefox";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

if (get_kb_item(kb_base + '/is_esr')) exit(0, 'The Mozilla Firefox installation is in the ESR branch.');

mozilla_check_version(product:'firefox', version:version, path:path, esr:FALSE, fix:'49.0.2', min:'48', severity:SECURITY_HOLE);
