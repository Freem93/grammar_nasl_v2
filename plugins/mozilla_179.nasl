#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18813);
  script_version("$Revision: 1.21 $");

  script_cve_id(
    "CVE-2004-0718", 
    "CVE-2005-1937", 
    "CVE-2005-2260", 
    "CVE-2005-2261", 
    "CVE-2005-2263", 
    "CVE-2005-2265", 
    "CVE-2005-2266", 
    "CVE-2005-2268", 
    "CVE-2005-2269", 
    "CVE-2005-2270"
  );
  script_bugtraq_id(14242);
  script_osvdb_id(
    59834,
    17397,
    17913,
    17942,
    17964,
    17966,
    17968,
    17969,
    17970,
    7296
  );

  script_name(english:"Mozilla Browser < 1.7.9 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote host contains multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote version of this software contains various security issues,
one of which may allow an attacker to execute arbitrary code on the
remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www-archive.mozilla.org/security/announce/2005/mfsa2005-45.html" );
 script_set_attribute(attribute:"see_also", value:"http://www-archive.mozilla.org/security/announce/2005/mfsa2005-46.html" );
 script_set_attribute(attribute:"see_also", value:"http://www-archive.mozilla.org/security/announce/2005/mfsa2005-48.html" );
 script_set_attribute(attribute:"see_also", value:"http://www-archive.mozilla.org/security/announce/2005/mfsa2005-50.html" );
 script_set_attribute(attribute:"see_also", value:"http://www-archive.mozilla.org/security/announce/2005/mfsa2005-51.html" );
 script_set_attribute(attribute:"see_also", value:"http://www-archive.mozilla.org/security/announce/2005/mfsa2005-52.html" );
 script_set_attribute(attribute:"see_also", value:"http://www-archive.mozilla.org/security/announce/2005/mfsa2005-54.html" );
 script_set_attribute(attribute:"see_also", value:"http://www-archive.mozilla.org/security/announce/2005/mfsa2005-55.html" );
 script_set_attribute(attribute:"see_also", value:"http://www-archive.mozilla.org/security/announce/2005/mfsa2005-56.html" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Sep/235");
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla 1.7.9 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Mozilla Suite/Firefox compareTo() Code Execution');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/06/30");
 script_set_attribute(attribute:"patch_publication_date", value: "2004/06/22");
 script_cvs_date("$Date: 2016/11/28 21:52:56 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe",value:"cpe:/a:mozilla:mozilla");
script_set_attribute(attribute:"cpe",value:"cpe:/a:mozilla:firefox");
script_set_attribute(attribute:"cpe",value:"cpe:/a:mozilla:thunderbird");
script_set_attribute(attribute:"cpe",value:"cpe:/a:mozilla:firebirdsql:firebird");
script_set_attribute(attribute:"cpe",value:"cpe:/a:netscape:navigator");
script_end_attributes();

  script_summary(english:"Checks for Mozilla < 1.7.9");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Version");
  exit(0);
}

#

include("misc_func.inc");


ver = read_version_in_kb("Mozilla/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 1 ||
  (
    ver[0] == 1 &&
    (
      ver[1] < 7 ||
      (ver[1] == 7 && ver[2] < 9)
    )
  )
) security_hole(get_kb_item("SMB/transport"));
