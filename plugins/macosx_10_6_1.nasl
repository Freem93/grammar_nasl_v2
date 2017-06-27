#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(40946);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2009-1862", "CVE-2009-1863", "CVE-2009-1864", "CVE-2009-1865", "CVE-2009-1866",
                "CVE-2009-1867", "CVE-2009-1868", "CVE-2009-1869", "CVE-2009-1870");
  script_bugtraq_id(35759, 36349);
  script_osvdb_id(
    56282,
    56771,
    56772,
    56773,
    56774,
    56775,
    56776,
    56777,
    56778
  );

  script_name(english:"Mac OS X 10.6.x < 10.6.1 Multiple Vulnerabilities");
  script_summary(english:"Check the version of Mac OS X");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is missing a Mac OS X update that fixes various
security issues."  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is running a version of Mac OS X 10.6.x that is prior
to 10.6.1. 

Mac OS X 10.6.1 contains security fixes for the following product :

  - Flash Player plug-in"  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT3864"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2009/Sep/msg00003.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/advisories/17867"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Mac OS X 10.6.1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(59, 94, 119, 189, 200, 264);
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/09/10"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/09/11"
  );
 script_cvs_date("$Date: 2016/11/28 21:06:37 $");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
 
  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");

 exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if (!os) {
  os = get_kb_item("Host/OS");
  c = get_kb_item("Host/OS/Confidence");
  if ( isnull(os) || c <= 70 ) exit(0);
}
if (!os) exit(1, "The 'Host/OS' KB item is missing.");

if (ereg(pattern:"Mac OS X 10\.6($|\.0)", string:os)) security_hole(0);
else exit(0, "The host is not affected.");
