#
# (C) Tenable Network Security, Inc.
#

# Ref: 
# Date: Mon, 05 May 2003 16:44:47 -0300
# From: CORE Security Technologies Advisories <advisories@coresecurity.com>
# To: Bugtraq <bugtraq@securityfocus.com>,
# Subject: CORE-2003-0303: Multiple Vulnerabilities in Mirabilis ICQ client
#


include("compat.inc");

if(description)
{
 script_id(11572);
 script_version("$Revision: 1.14 $");
 script_cve_id("CVE-1999-1418", "CVE-1999-1440", "CVE-2000-0046", "CVE-2000-0564",
               "CVE-2000-0552", "CVE-2001-0367", "CVE-2002-0028", "CVE-2001-1305",
               "CVE-2003-0235", "CVE-2003-0236", "CVE-2003-0237", "CVE-2003-0238",
               "CVE-2003-0239");
 script_bugtraq_id( 132, 246, 929, 1307, 2664, 3226, 3813, 7461, 7462, 7463, 7464, 7465, 7466);
 script_xref(name:"OSVDB", value:"1376");
 script_xref(name:"OSVDB", value:"2018");
 script_xref(name:"OSVDB", value:"6334");
 script_xref(name:"OSVDB", value:"7740");
 script_xref(name:"OSVDB", value:"7741");
 script_xref(name:"OSVDB", value:"7742");
 script_xref(name:"OSVDB", value:"7743");
 script_xref(name:"OSVDB", value:"7744");
 script_xref(name:"OSVDB", value:"7745");
 script_xref(name:"OSVDB", value:"7966");
 script_xref(name:"OSVDB", value:"9537");
 script_xref(name:"OSVDB", value:"9538");
 script_xref(name:"OSVDB", value:"9544");
 script_xref(name:"OSVDB", value:"9545");

 script_name(english:"ICQ < 2003b Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a program that is affected by
multiple flaws." );
 script_set_attribute(attribute:"description", value:
"There are multiple flaws in versions of ICQ before 2003b, including
some that may allow an attacker to execute arbitrary code on the
remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.coresecurity.com/index.php5?module=ContentMod&action=item&id=1221" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ICQ 2003b or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/01/01");
 script_cvs_date("$Date: 2011/03/07 01:17:51 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 script_summary(english:"Checks version of ICQ installed");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("icq_installed.nasl");
 script_require_keys("SMB/ICQ/Version");
 exit(0);
}

#

include("smb_func.inc");

ver = get_kb_item("SMB/ICQ/Version");
if (ver) {
  iver = split(ver, sep:'.', keep:FALSE);
  # Check whether it's an affected version.
  #
  # nb: 2003b == "5.5.6.3916"
  if (
    int(iver[0]) < 5 ||
    (
      int(iver[0]) == 5 &&
      (
        int(iver[1]) < 5 ||
        (
          int(iver[1]) == 5 &&
          (
            int(iver[2]) < 6 ||
            (int(iver[2]) == 6 && int(iver[3]) < 3916)
          )
        )
      )
    )
  ) security_hole(kb_smb_transport());
}
