#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(20735);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2006-0236");
  script_bugtraq_id(16271);
  script_osvdb_id(22510);

  script_name(english:"Mozilla Thunderbird < 1.5 Attachment Extension Spoofing");
  script_summary(english:"Checks for Mozilla Thunderbird < 1.5");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote version of Mozilla Thunderbird is affected by an attachment
spoofing vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is using Mozilla Thunderbird, an email client. 

The remote version of this software does not display attachments
correctly in emails.  Using an overly-long filename and
specially crafted Content-Type headers, an attacker may be able to
leverage this issue to spoof the file extension and associated file
type icon and trick a user into executing an arbitrary program." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2005-22/advisory/" );
 script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=300246" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird 1.5 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/01/18");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/01/17");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/01/11");
 script_cvs_date("$Date: 2013/05/23 15:37:58 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'1.5', severity:SECURITY_WARNING);