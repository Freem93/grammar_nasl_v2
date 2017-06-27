#
# (C) Tenable Network Security, Inc.
#


if (NASL_LEVEL < 3004) exit(0);



include("compat.inc");

if (description)
{
  script_id(21627);
  script_version("$Revision: 1.20 $");

  script_cve_id(
    "CVE-2006-1942", 
    "CVE-2006-2775", 
    "CVE-2006-2776", 
    "CVE-2006-2777", 
    "CVE-2006-2778", 
    "CVE-2006-2779", 
    "CVE-2006-2780", 
    "CVE-2006-2782", 
    "CVE-2006-2783", 
    "CVE-2006-2784", 
    "CVE-2006-2785", 
    "CVE-2006-2786", 
    "CVE-2006-2787"
  );
  script_bugtraq_id(18228);
  script_osvdb_id(
    24713,
    26298,
    26299,
    26300,
    26301,
    26302,
    26303,
    26304,
    26305,
    26306,
    26307,
    26308,
    26309,
    26310,
    26311,
    26313,
    26314,
    26315
  );

  script_name(english:"Firefox < 1.5.0.4 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The installed version of Firefox is affected by various security issues,
some of which may lead to execution of arbitrary code on the affected
host subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-31.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-32.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-33.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-34.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-35.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-36.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-37.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-38.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-39.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-41.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-42.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-43.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 1.5.0.4 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 94);

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/06/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/05/05");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/06/01");
 script_cvs_date("$Date: 2016/11/28 21:52:56 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'1.5.0.4', severity:SECURITY_HOLE);