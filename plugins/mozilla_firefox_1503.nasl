#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(21322);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2006-1993");
  script_bugtraq_id(17671);
  script_osvdb_id(24967);

  script_name(english:"Firefox < 1.5.0.3 iframe.contentWindow.focus() Overflow");
  script_summary(english:"Checks Firefox version number");

 script_set_attribute(attribute:"synopsis", value:
"A web browser on the remote host may be prone to a denial of service
attack." );
 script_set_attribute(attribute:"description", value:
"The installed version of Firefox may allow a malicious site to crash
the browser and potentially to run malicious code when attempting to
use a deleted controller context. 

Successful exploitation requires that 'designMode' be turned on." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/431878/100/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-30.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 1.5.0.3 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/05/04");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/04/23");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/05/02");
 script_cvs_date("$Date: 2013/05/23 15:37:57 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'1.5.0.3', severity:SECURITY_WARNING);