#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80521);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/17 17:02:53 $");

  script_cve_id(
    "CVE-2014-8639",
    "CVE-2014-8638",
    "CVE-2014-8634",
    "CVE-2014-8635"
  );
  script_bugtraq_id(
    72046,
    72047,
    72049,
    72050
  );
  script_osvdb_id(
    117007,
    117003,
    116998,
    117001,
    116993,
    116994,
    116995,
    116996,
    116997,
    117000,
    117002,
    116999
  );

  script_name(english:"Mozilla Thunderbird < 31.4 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version of Thunderbird.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a mail client that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote Mac OS X host is
prior to 31.4. It is, therefore, affected by the following
vulnerabilities :

  - Multiple unspecified memory safety issues exist within
    the browser engine. (CVE-2014-8634, CVE-2014-8635)

  - A flaw exists in 'navigator.sendBeacon()' in which it
    does not follow the cross-origin resource sharing
    specification. This results in requests from
    'sendBeacon()' lacking an 'origin' header. This allows
    malicious sites to perform XSRF attacks. (CVE-2014-8638)

  - A flaw exists when receiving 407 Proxy Authentication
    responses with a 'set-cookie' header. This can allow
    a session-fixation attack. (CVE-2014-8639)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-01/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-03/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-04/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Thunderbird 31.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_thunderbird_installed.nasl");
  script_require_keys("MacOSX/Thunderbird/Installed");

  exit(0);
}

include("mozilla_version.inc");

kb_base = "MacOSX/Thunderbird";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

if (get_kb_item(kb_base + '/is_esr')) exit(0, 'The Mozilla Thunderbird install is in the ESR branch.');

mozilla_check_version(product:'thunderbird', version:version, path:path, esr:FALSE, fix:'31.4', min:'31.0', severity:SECURITY_HOLE, xss:FALSE, xsrf:TRUE);
