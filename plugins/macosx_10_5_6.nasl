#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3004) exit(0);



include("compat.inc");

if (description)
{
  script_id(35111);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/11/28 21:06:37 $");

  script_cve_id(
    "CVE-2008-1391", 
    "CVE-2008-3170", 
    "CVE-2008-3623", 
    "CVE-2008-4217", 
    "CVE-2008-4218",
    "CVE-2008-4219", 
    "CVE-2008-4220", 
    "CVE-2008-4221", 
    "CVE-2008-4222", 
    "CVE-2008-4223",
    "CVE-2008-4224", 
    "CVE-2008-4234", 
    "CVE-2008-4236", 
    "CVE-2008-4237", 
    "CVE-2008-4818",
    "CVE-2008-4819", 
    "CVE-2008-4820", 
    "CVE-2008-4821", 
    "CVE-2008-4822", 
    "CVE-2008-4823",
    "CVE-2008-4824"
  );
  script_bugtraq_id(
    28479, 
    30192, 
    32129, 
    32291, 
    32870, 
    32872, 
    32873, 
    32874, 
    32875, 
    32876, 
    32877, 
    32879, 
    32880, 
    32881
  );
  script_osvdb_id(
    43837,
    47275,
    49753,
    49780,
    49781,
    49783,
    49785,
    49790,
    49939,
    49958,
    50861,
    50923,
    50924,
    50925,
    50927,
    50928,
    50958,
    50982,
    50983,
    50984,
    53100
  );

  script_name(english:"Mac OS X 10.5.x < 10.5.6 Multiple Vulnerabilities");
  script_summary(english:"Check the version of Mac OS X");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes various
security issues." );
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.5.x that is prior
to 10.5.6. 

Mac OS X 10.5.6 contains security fixes for the following products :

  - ATS
  - BOM
  - CoreGraphics
  - CoreServices
  - CoreTypes
  - Flash Player Plug-in
  - Kernel
  - Libsystem
  - Managed Client
  - network_cmds
  - Podcast Producer
  - UDF" );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT3338" );
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/Dec/msg00000.html" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mac OS X 10.5.6 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 79, 119, 189, 200, 264, 287, 399);

  script_set_attribute(attribute:"plugin_publication_date", value: "2008/12/16");
  script_set_attribute(attribute:"patch_publication_date", value: "2008/12/15");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if (!os) os = get_kb_item("Host/OS");
if (!os) exit(0);

if (ereg(pattern:"Mac OS X 10\.5\.[0-5]([^0-9]|$)", string:os)) 
  security_hole(0);
