#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56037);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/28 21:52:56 $");

  script_name(english:"Firefox 3.6.x < 3.6.21 Out-of-Date CA List");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
an out-of-date certificate authority list.");
  script_set_attribute(attribute:"description", value:
"The installed version of Firefox 3.6.x is earlier than 3.6.21 and is 
potentially affected by an out-of-date certificate authority list. 
Due to the issuance of several fraudulent SSL certificates, the 
certificate authority DigiNotar has been disabled in Mozilla Firefox.
");

  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-34.html");

  # http://blog.mozilla.com/security/2011/08/29/fraudulent-google-com-certificate/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9351126b");
  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 3.6.21 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");


  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/31");

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

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'3.6.21', min:'3.6', severity:SECURITY_WARNING);