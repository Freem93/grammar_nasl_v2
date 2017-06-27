#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25148);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2007-2418");
  script_bugtraq_id(23781);
  script_osvdb_id(35720);

  script_name(english:"Trillian < 3.1.5.1 XMPP Decoding Heap Overflow");
  script_summary(english:"Checks version number of Trillian");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an instant messaging application which is susceptible
to a heap overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of Trillian installed on the remote host contains a buffer
overflow vulnerability which can be triggered when decoding a malformed
XMPP (eXtensible Messaging and Presence Protocol) message. 

To exploit this flaw, an attacker would need to send a specially crafted
XMPP message to a user of this program, thus causing arbitrary code 
execution." );
 script_set_attribute(attribute:"see_also", value:"http://dvlabs.tippingpoint.com/advisory/TPTI-07-06" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Trillian 3.1.5.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/05/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/05/01");
 script_cvs_date("$Date: 2011/04/13 20:23:35 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:trillian:trillian");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");

  script_dependencies("trillian_installed.nasl");
  script_require_keys("SMB/Trillian/Version");

  exit(0);
}


ver = get_kb_item("SMB/Trillian/Version");
# Trillian > 3.1 is affected
if (ver && ver =~ "^3\.1\.([0-4]\.|5\.0)" )
  security_hole(get_kb_item("SMB/transport"));
