#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if (description)
{
  script_id(27625);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2007-2395", "CVE-2007-3750", "CVE-2007-3751", "CVE-2007-4672", 
                "CVE-2007-4674", "CVE-2007-4675", "CVE-2007-4676", "CVE-2007-4677");
  script_bugtraq_id(26338, 26339, 26340, 26341, 26342, 26344, 26345, 26443);
  script_osvdb_id(38544, 38545, 38546, 38547, 38548, 38549, 38550, 43716);

  script_name(english:"QuickTime < 7.3 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of QuickTime on Mac OS X");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains an application that is affected by
multiple issues." );
 script_set_attribute(attribute:"description", value:
"The version of QuickTime installed on the remote Mac OS X host is older
than 7.3.  Such versions contain several vulnerabilities that may
allow an attacker to execute arbitrary code on the remote host if he
can trick the user to open a specially crafted file with QuickTime." );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=306896" );
 script_set_attribute(attribute:"solution", value:
"Either use QuickTime's Software Update preference to upgrade to the
latest version or manually upgrade to QuickTime 7.3 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119, 189);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/11/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/11/06");
 script_cvs_date("$Date: 2016/11/28 21:06:38 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/11/05");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
  script_dependencies("macosx_Quicktime652.nasl");
  script_require_keys("MacOSX/QuickTime/Version");
  exit(0);
}

#

ver = get_kb_item("MacOSX/QuickTime/Version");
if (! ver ) exit(0);

version = split(ver, sep:'.', keep:FALSE);
if ( (int(version[0]) < 7) ||
     (int(version[0]) == 7 && int(version[1]) < 3 ) ) security_hole(0);
