#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71042);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/17 16:53:09 $");

  script_cve_id("CVE-2013-5605");
  script_bugtraq_id(63737);
  script_osvdb_id(99746);

  script_name(english:"Thunderbird ESR < 17.0.11 Null_Cipher Code Execution (Mac OS X)");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Mac OS X host contains a mail client that is potentially
affected by a code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of Thunderbird ESR is prior to 17.0.11 and is,
therefore, potentially affected by a code execution vulnerability
related to the function 'Null_Cipher' in the file 'ssl/ssl3con.c' and
handling handshake packets."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-103.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/en-US/thunderbird/17.0.11esr/releasenotes/");
  script_set_attribute(attribute:"see_also", value:"https://developer.mozilla.org/en-US/docs/NSS/NSS_3.14.5_release_notes");

  script_set_attribute(attribute:"solution", value:"Upgrade to Thunderbird ESR 17.0.11 or later.");
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

is_esr = get_kb_item(kb_base+"/is_esr");
if (isnull(is_esr)) audit(AUDIT_NOT_INST, "Mozilla Thunderbird ESR");

mozilla_check_version(product:'thunderbird', version:version, path:path, esr:TRUE, fix:'17.0.11', severity:SECURITY_HOLE, xss:FALSE);
