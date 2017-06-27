#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10835);
 script_version("$Revision: 1.31 $");

 script_cve_id("CVE-2001-0876", "CVE-2001-0877");
 script_bugtraq_id(3723);

 script_name(english:"MS01-059: Unchecked Buffer in Universal Plug and Play can Lead to System Compromise (315000)");
 script_summary(english:"Determines the presence of hotfix Q315000");
 
 script_set_attribute(
  attribute:"synopsis",
  value:
"The Universal Plug and Play service on the remote host is prone to
denial of service and buffer overflow attacks." );
 script_set_attribute(
  attribute:"description", 
  value:
"Using a specially crafted NOTIFY directive, a remote attacker can
cause code to run in the context of the Universal Plug and Play (UPnP)
subsystem or possibly launch a denial of service attack against the
affected host.

Note that, under Windows XP, the UPnP subsystem operates with SYSTEM
privileges." );
 script_set_attribute(
  attribute:"solution", 
  value:
"Microsoft has released a set of patches for Windows 98, 98SE, ME, and
XP :

http://technet.microsoft.com/en-us/security/bulletin/ms01-059" );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/01/25");
 script_set_attribute(attribute:"patch_publication_date", value: "2001/12/20");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/12/20");
 script_cvs_date("$Date: 2016/05/06 17:22:01 $");
 script_osvdb_id(692, 697);
 script_xref(name:"MSFT", value: "MS01-059");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");


if ( hotfix_check_sp(xp:1) <= 0 ) exit(0);

if ( hotfix_missing(name:"315000") > 0  )
  security_hole(kb_smb_transport());
