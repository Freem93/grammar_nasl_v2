#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3004) exit(0);

include("compat.inc");

if (description)
{
  script_id(40502);
  script_version("$Revision: 1.20 $");

  script_cve_id("CVE-2008-0674", "CVE-2008-1372", "CVE-2009-0040", "CVE-2009-0151", "CVE-2009-1235",
                "CVE-2009-1720", "CVE-2009-1721", "CVE-2009-1722", "CVE-2009-1723", "CVE-2009-1726",
                "CVE-2009-1727", "CVE-2009-1728", "CVE-2009-2188", "CVE-2009-2190", "CVE-2009-2191",
                "CVE-2009-2192", "CVE-2009-2193", "CVE-2009-2194");
  script_bugtraq_id(27786, 28286, 33827, 34203, 35838, 36025);
  script_osvdb_id(
    41989,
    43425,
    53315,
    53316,
    53317,
    53333,
    56707,
    56708,
    56709,
    56836,
    56838,
    56839,
    56840,
    56841,
    56842,
    56843,
    56844,
    56845,
    56846,
    56847
  );

  script_name(english:"Mac OS X 10.5.x < 10.5.8 Multiple Vulnerabilities");
  script_summary(english:"Check the version of Mac OS X");

  script_set_attribute( attribute:"synopsis",  value:
"The remote host is missing a Mac OS X update that fixes various
security issues."  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is running a version of Mac OS X 10.5.x that is prior
to 10.5.8. 

Mac OS X 10.5.8 contains security fixes for the following products :

  - bzip2
  - CFNetwork
  - ColorSync
  - CoreTypes
  - Dock
  - Image RAW
  - ImageIO
  - Kernel
  - launchd
  - Login Window
  - MobileMe
  - Networking
  - XQuery"  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT3757"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2009/Aug/msg00001.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Mac OS X 10.5.8 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(16, 94, 119, 134, 189, 255, 264, 399);
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/08/05"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/08/05"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/08/05"
  );
 script_cvs_date("$Date: 2016/11/28 21:06:37 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
 
  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");

 exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if (!os) os = get_kb_item("Host/OS");
if (!os) exit(1, "The 'Host/MacOSX/Version' and 'Host/OS' KB items are missing.");

if (ereg(pattern:"Mac OS X 10\.5\.[0-7]([^0-9]|$)", string:os)) security_hole(0);
else exit(0, "The host is not affected.");
