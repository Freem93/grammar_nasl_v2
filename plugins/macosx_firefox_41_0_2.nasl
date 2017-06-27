#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86417);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/04/28 20:52:58 $");

  script_cve_id("CVE-2015-7184");
  script_osvdb_id(128954);

  script_name(english:"Firefox < 41.0.2 'fetch' API Cross-Origin Bypass (Mac OS X)");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
a cross-origin restriction bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Mac OS X host is prior
to 41.0.2. It is, therefore, affected by a cross-origin restriction
bypass vulnerability in the fetch() API due to an incorrect
implementation of the Cross-Origin Resource Sharing (CORS)
specification. A remote attacker can exploit this, via a malicious
website, to access private data from other origins.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-115/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 41.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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

mozilla_check_version(product:'firefox', version:version, path:path, esr:FALSE, fix:'41.0.2', severity:SECURITY_WARNING);
