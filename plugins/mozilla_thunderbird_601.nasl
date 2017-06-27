#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56040);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/28 21:52:57 $");

  script_name(english:"Mozilla Thunderbird < 6.0.1 Out-of-Date CA List");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client that may be affected
by an out-of-date certificate authority list.");
  script_set_attribute(attribute:"description", value:
"The installed version of Thunderbird is earlier than 6.0.1 and thus,
is potentially affected by an out-of-date certificate authority list.
Due to the issuance of several fraudulent SSL certificates, 
the certificate authority DigiNotar has been disabled in Mozilla 
Thunderbird.");

  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-34.html");

  # http://blog.mozilla.com/security/2011/08/29/fraudulent-google-com-certificate/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9351126b");
  script_set_attribute(attribute:"solution", value:"Upgrade to Thunderbird 6.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");


  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'6.0.1', skippat:'^3\\.1\\.', severity:SECURITY_WARNING);