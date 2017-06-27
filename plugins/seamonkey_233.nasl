#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56123);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:22:12 $");

  script_name(english:"SeaMonkey < 2.3.3 Untrusted CA");
  script_summary(english:"Checks version of SeaMonkey");

  script_set_attribute(attribute:"synopsis",value:
"The remote Windows host contains a web browser that contains support
for an untrustworthy certificate authority.");
  script_set_attribute(attribute:"description",value:
"The installed version of SeaMonkey is earlier than 2.3.3.  Due to a
recent attack against certificate authority DigiNotar, Mozilla has
added explicit distrust to the DigiNotar root certificate and several
intermediates in this version of SeaMonkey. 

Note this is a further fix to MFSA 2011-34, which removed the
DigiNotar root certificate.");

  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-35.html");

  # https://bugzilla.mozilla.org/buglist.cgi?bug_id=683261,683449,683883
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a36daf9d");
  script_set_attribute(attribute:"solution", value:"Upgrade to SeaMonkey 2.3.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");


  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:seamonkey");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("SeaMonkey/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/SeaMonkey/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "SeaMonkey");

mozilla_check_version(installs:installs, product:'seamonkey', fix:'2.3.3', severity:SECURITY_WARNING);