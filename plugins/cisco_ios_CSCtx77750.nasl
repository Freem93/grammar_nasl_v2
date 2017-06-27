#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61577);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/04 18:02:13 $");

  script_cve_id("CVE-2012-1361");
  script_bugtraq_id(54828);
  script_osvdb_id(84502);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtx77750");

  script_name(english:"Cisco IOS MMoH Information Leak");
  script_summary(english:"Checks IOS version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Cisco IOS device has an information leak vulnerability. 
When the H.323 Multicast Music on Hold feature is enabled and in use,
PSTN callers may be able to hear crosstalk."
  );
  # http://tools.cisco.com/Support/BugToolKit/search/getBugDetails.do?method=fetchBugDetails&bugId=CSCtx77750
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?960b5c9f");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to one of the non-vulnerable versions listed in the bug
details for CSCtx77750."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (version == '15.0(1)XA1')
  security_warning(0);
else if (version == '15.0(1)XA2')
  security_warning(0);
else if (version == '15.0(1)XA3')
  security_warning(0);
else if (version == '15.0(1)XA4')
  security_warning(0);
else if (version == '15.0(1)XA5')
  security_warning(0);
else if (version == '15.1(4r)')
  security_warning(0);
else if (version == '15.1(4r)M1')
  security_warning(0);
else if (version == '15.1(1)T')
  security_warning(0);
else if (version == '15.1(1)T1')
  security_warning(0);
else if (version == '15.1(1)T2')
  security_warning(0);
else if (version == '15.1(1)T3')
  security_warning(0);
else if (version == '15.1(1)T4')
  security_warning(0);
else if (version == '15.1(1r)T1')
  security_warning(0);
else if (version == '15.1(1r)T2')
  security_warning(0);
else if (version == '15.1(1r)T3')
  security_warning(0);
else if (version == '15.1(1r)T4')
  security_warning(0);
else if (version == '15.1(2)T')
  security_warning(0);
else if (version == '15.1(2)T0a')
  security_warning(0);
else if (version == '15.1(2)T1')
  security_warning(0);
else if (version == '15.1(2)T2')
  security_warning(0);
else if (version == '15.1(2)T2a')
  security_warning(0);
else if (version == '15.1(2)T3')
  security_warning(0);
else if (version == '15.1(2)T4')
  security_warning(0);
else if (version == '15.1(3)T')
  security_warning(0);
else if (version == '15.1(3)T1')
  security_warning(0);
else if (version == '15.1(3)T2')
  security_warning(0);
else if (version == '15.1(3)T3')
  security_warning(0);
else if (version == '15.1(2)GC')
  security_warning(0);
else if (version == '15.1(2)GC1')
  security_warning(0);
else if (version == '15.1(2r)GC')
  security_warning(0);
else if (version == '15.1(2r)GC1')
  security_warning(0);
else if (version == '15.1(1)XB')
  security_warning(0);
else if (version == '15.1(1)XB1')
  security_warning(0);
else if (version == '15.1(1)XB2')
  security_warning(0);
else if (version == '15.1(1)XB3')
  security_warning(0);
else if (version == '15.1(9999)CCAI')
  security_warning(0);
else
  audit(AUDIT_HOST_NOT, "affected");
