#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(20958);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2011/08/29 16:27:27 $");

  script_cve_id("CVE-2006-0189");
  script_bugtraq_id(16213);
  script_osvdb_id(22348);

  script_name(english:"eStara SoftPhone SIP Packet SDP Data attribute Field Overflow");
  script_summary(english:"Checks version number of eStara SoftPhone");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote SIP client is prone to a buffer overflow attack." );
  script_set_attribute(attribute:"description", value:
"The version of SoftPhone installed on the remote host reportedly fails
to properly handle SIP packets with long 'a=' lines in the SDP data. 
An unauthenticated, remote attacker may be able to exploit this flaw to
overflow a buffer and execute arbitrary code on the remote host." );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/421596/100/0/threaded" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to eStara SoftPhone version 3.0.1.47 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value: "2006/02/22");
  script_set_attribute(attribute:"vuln_publication_date", value: "2006/01/11");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("estara_softphone_installed.nasl");
  script_require_keys("SMB/SoftPhone/Version");

  exit(0);
}


include("smb_func.inc");


ver = get_kb_item("SMB/SoftPhone/Version");
if (ver) {
  iver = split(ver, sep:'.', keep:FALSE);
  # Check whether it's an affected version.
  if (
    int(iver[0]) < 3 ||
    (
      int(iver[0]) == 3 && 
      int(iver[1]) == 0 &&
      (
        int(iver[2]) < 1 ||
        (int(iver[2]) == 1 && int(iver[3]) < 47)
      )
    )
  ) security_hole(kb_smb_transport());
}
