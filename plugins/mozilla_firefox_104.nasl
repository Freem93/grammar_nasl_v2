#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(18243);
 script_version("$Revision: 1.26 $");

 script_cve_id(
  "CVE-2005-1476", 
  "CVE-2005-1477", 
  "CVE-2005-1531", 
  "CVE-2005-1532"
 );
 script_bugtraq_id(13544, 13641, 13645);
 script_osvdb_id(16185, 16186, 16576, 16605, 79345, 79346);

 script_name(english:"Firefox < 1.0.4 Multiple Vulnerabilities");
 script_summary(english:"Determines the version of Firefox");

 script_set_attribute( attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute( attribute:"description",  value:
"The installed version of Firefox is earlier than 1.0.4.  Such
versions have multiple vulnerabilities that may allow arbitrary
code execution." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.mozilla.org/security/announce/2005/mfsa2005-42.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.mozilla.org/security/announce/2005/mfsa2005-43.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.mozilla.org/security/announce/2005/mfsa2005-44.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Firefox 1.0.4 or later."
 );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/12");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/07");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/05/11");
 script_cvs_date("$Date: 2016/05/16 14:12:50 $");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("mozilla_org_installed.nasl");
 script_require_keys("Mozilla/Firefox/Version");
 exit(0);
}

#
include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'1.0.4', severity:SECURITY_HOLE);

