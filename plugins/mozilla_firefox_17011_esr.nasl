#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70947);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/16 14:12:50 $");

  script_cve_id("CVE-2013-5605");
  script_bugtraq_id(63737);
  script_osvdb_id(99746);

  script_name(english:"Firefox ESR < 17.0.11 Null_Cipher Code Execution");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains a web browser that is potentially
affected by a code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of Firefox ESR is a version prior to 17.0.11, and
is, therefore, potentially affected by a code execution vulnerability
related to the function 'Null_Cipher' in the file 'ssl/ssl3con.c' and
handling handshake packets."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-103.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/en-US/firefox/17.0.11/releasenotes/");
  script_set_attribute(attribute:"see_also", value:"https://developer.mozilla.org/en-US/docs/NSS/NSS_3.14.5_release_notes");

  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox ESR 17.0.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'17.0.11', severity:SECURITY_HOLE, xss:FALSE);
