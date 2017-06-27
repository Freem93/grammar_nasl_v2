#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57316);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/16 14:12:50 $");

  script_cve_id("CVE-2010-5074");
  script_bugtraq_id(51051);
  script_osvdb_id(77609);

  script_name(english:"Firefox < 4 CSS Browser History Disclosure Vulnerability");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The installed version of Firefox 3 is potentially affected by an
information disclosure vulnerability. 

The JavaScript function 'getComputedStyle', and functions like it, can
be used in a timing attack to determine if a browser has visited links
on the page.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2afc223d");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/en-US/firefox/4.0/releasenotes/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 4.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/15");

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

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'4.0', severity:SECURITY_WARNING);