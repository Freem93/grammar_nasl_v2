#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3004) exit(1);


include("compat.inc");

if(description)
{
 script_id(18064);
 script_version("$Revision: 1.20 $");

 script_cve_id(
   "CVE-2005-0752", 
   "CVE-2005-0989", 
   "CVE-2005-1153", 
   "CVE-2005-1154", 
   "CVE-2005-1154",
   "CVE-2005-1155", 
   "CVE-2005-1156",
   "CVE-2005-1157", 
   "CVE-2005-1158", 
   "CVE-2005-1159",
   "CVE-2005-1160"
 );
 script_bugtraq_id(
   12988, 
   13211, 
   13216, 
   13228, 
   13229, 
   13230, 
   13231, 
   13232, 
   13233
 );
 script_osvdb_id(
  15241,
  15682,
  15683,
  15684,
  15685,
  15686,
  15687,
  15688,
  15689,
  15690
 );

 script_name(english:"Firefox < 1.0.3 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote host contains multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote version of this software contains various security issues
that may allow an attacker to execute arbitrary code on the remote
host." );
 # http://web.archive.org/web/20050424025737/http://www.mozilla.org/security/announce/mfsa2005-33.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ceb3c0f7" );
 # http://web.archive.org/web/20050608082720/http://www.mozilla.org/security/announce/mfsa2005-34.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b7a2c667" );
 # http://web.archive.org/web/20050615075401/http://www.mozilla.org/security/announce/mfsa2005-35.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f22f8e9e" );
 # http://web.archive.org/web/20050528080947/http://www.mozilla.org/security/announce/mfsa2005-36.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b4c03071" );
 # http://web.archive.org/web/20050529084146/http://www.mozilla.org/security/announce/mfsa2005-37.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd46bb25" );
 # http://web.archive.org/web/20050531081142/http://www.mozilla.org/security/announce/mfsa2005-38.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0cd66aa" );
 # http://web.archive.org/web/20050602085103/http://www.mozilla.org/security/announce/mfsa2005-39.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c11e0f3c" );
 # http://web.archive.org/web/20050622083441/http://www.mozilla.org/security/announce/mfsa2005-40.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?50a4385d" );
 # http://web.archive.org/web/20050625084141/http://www.mozilla.org/security/announce/mfsa2005-41.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d0dac446" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 1.0.3 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/03/31");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/04/18");
 script_cvs_date("$Date: 2013/05/23 15:37:57 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
script_end_attributes();

 script_summary(english:"Determines the version of Firefox");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'1.0.3', severity:SECURITY_HOLE);