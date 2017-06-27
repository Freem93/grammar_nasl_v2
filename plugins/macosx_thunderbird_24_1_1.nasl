#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71043);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/17 17:02:53 $");

  script_cve_id(
    "CVE-2013-1741",
    "CVE-2013-5605",
    "CVE-2013-5606",
    "CVE-2013-5607"
  );
  script_bugtraq_id(63736, 63737, 63738, 63802);
  script_osvdb_id(99746, 99747, 99748, 101422);

  script_name(english:"Thunderbird < 24.1 NSS and NSPR Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Mac OS X host contains a mail client that is potentially
affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of Thunderbird is earlier than 24.1.1 and is,
therefore, potentially affected by the following vulnerabilities :

  - An error exists related to handling input greater than
    half the maximum size of the 'PRUint32' value.
    (CVE-2013-1741)

  - An error exists in the 'Null_Cipher' function in the
    file 'ssl/ssl3con.c' related to handling invalid
    handshake packets that could allow arbitrary code
    execution. (CVE-2013-5605)

  - An error exists in the 'CERT_VerifyCert' function in
    the file 'lib/certhigh/certvfy.c' that could allow
    invalid certificates to be treated as valid.
    (CVE-2013-5606)

  - An integer truncation error exists in the function
    'PL_ArenaAllocate' in the Netscape Portable Runtime
    (NSPR) library. (CVE-2013-5607)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-103.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/en-US/thunderbird/24.1.1/releasenotes/");
  script_set_attribute(attribute:"see_also", value:"https://developer.mozilla.org/en-US/docs/NSS/NSS_3.15.3_release_notes");

  script_set_attribute(attribute:"solution", value:"Upgrade to Thunderbird 24.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

mozilla_check_version(product:'thunderbird', version:version, path:path, esr:FALSE, fix:'24.1.1', severity:SECURITY_HOLE, xss:FALSE);
