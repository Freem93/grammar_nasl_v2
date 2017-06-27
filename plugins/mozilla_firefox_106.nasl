#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(19719);
  script_version("$Revision: 1.28 $");

  script_cve_id(
    "CVE-2005-2602", 
    "CVE-2005-2701", 
    "CVE-2005-2702", 
    "CVE-2005-2703", 
    "CVE-2005-2704",
    "CVE-2005-2705", 
    "CVE-2005-2706", 
    "CVE-2005-2707", 
    "CVE-2005-2871", 
    "CVE-2005-3089"
  );
  script_bugtraq_id(
    14526, 
    14784, 
    14916, 
    14917, 
    14918, 
    14919, 
    14920, 
    14921, 
    14923, 
    14924
  );
  script_osvdb_id(
    18691,
    19255,
    19615,
    19643,
    19644,
    19645,
    19646,
    19647,
    19648,
    19649,
    59850
  );

  script_name(english:"Firefox < 1.0.7 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"A web browser on the remote host is prone to multiple flaws, including
arbitrary code execution." );
 script_set_attribute(attribute:"description", value:
"The remote host is using Firefox, an alternative web browser. 

The installed version of Firefox contains various security issues,
several of which are critical as they can be easily exploited to
execute arbitrary shell code on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/407704" );
 script_set_attribute(attribute:"see_also", value:"http://security-protocols.com/advisory/sp-x17-advisory.txt" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/idn.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2005/mfsa2005-58.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 1.0.7 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(94);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/08/09");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/09/09");
 script_cvs_date("$Date: 2013/05/23 15:37:57 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
script_end_attributes();

  script_summary(english:"Determines the version of Firefox");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'1.0.7', severity:SECURITY_HOLE);