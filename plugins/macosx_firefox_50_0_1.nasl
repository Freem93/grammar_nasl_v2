#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95436);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/19 15:55:07 $");

  script_cve_id("CVE-2016-9078");
  script_bugtraq_id(94569);
  script_osvdb_id(147919);
  script_xref(name:"MFSA", value:"2016-91");

  script_name(english:"Mozilla Firefox 49.x < 50.0.1 HTTP Redirect Handling Same-origin Policy Bypass");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote macOS or Mac OS X host contains a web browser that is
affected by a same-origin policy bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox installed on the remote macOS or Mac
OS X host is 49.x prior to 50.0.1. It is, therefore, affected by a
same-origin policy bypass vulnerability in the
GetChannelResultPrincipal() function in nsScriptSecurityManager.cpp
due to improper handling of HTTP redirects to 'data: URLs'. An
unauthenticated, remote attacker can exploit this to bypass the
same-origin policy.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-91/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 50.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/01");

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

mozilla_check_version(product:'firefox', version:version, path:path, esr:FALSE, fix:'50.0.1', min:'49', severity:SECURITY_WARNING);
