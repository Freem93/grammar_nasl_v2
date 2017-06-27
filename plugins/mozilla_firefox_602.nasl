#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56120);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/28 21:52:57 $");

  script_name(english:"Firefox < 6.0.2 Untrusted CA");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that contains support
for an untrustworthy certificate authority.");
  script_set_attribute(attribute:"description", value:
"The installed version of Firefox is earlier than 6.0.2.  Due to a
recent attack against certificate authority DigiNotar, Mozilla has
added explicit distrust to the DigiNotar root certificate and several
intermediates in this version of Firefox. 

Note this is a further fix to MFSA 2011-34, which removed the
DigiNotar root certificate.");

  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-35.html");

  # https://bugzilla.mozilla.org/buglist.cgi?bug_id=683261,683449,683883
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a36daf9d");
  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 6.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");


  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'6.0.2', skippat:'^3\\.6\\.', severity:SECURITY_WARNING);